const { ResourceExplorer2Client, SearchCommand } = require("@aws-sdk/client-resource-explorer-2");
const { SQSClient, SendMessageBatchCommand } = require("@aws-sdk/client-sqs");
const { IAMClient, ListUsersCommand, ListRolesCommand, ListPoliciesCommand } = require("@aws-sdk/client-iam");
const { Route53Client, ListHostedZonesCommand } = require("@aws-sdk/client-route-53");
const { CloudFrontClient, ListDistributionsCommand } = require("@aws-sdk/client-cloudfront");
const { ACMClient, ListCertificatesCommand } = require("@aws-sdk/client-acm");
const { SecretsManagerClient, ListSecretsCommand } = require("@aws-sdk/client-secrets-manager");

const sqs = new SQSClient({});
const explorer = new ResourceExplorer2Client({});
const iam = new IAMClient({});
const route53 = new Route53Client({});
const cloudfront = new CloudFrontClient({ region: "us-east-1" });
const acm = new ACMClient({ region: "us-east-1" });
const secretsMgr = new SecretsManagerClient({});

const QUEUE_URL = process.env.SQS_QUEUE_URL;
const ACCOUNT_ID = process.env.AWS_ACCOUNT_ID || "";

const chunkArray = (arr, size) =>
  Array.from({ length: Math.ceil(arr.length / size) }, (_, i) => arr.slice(i * size, i * size + size));

async function flushToSqs(buffer) {
  if (!buffer.length) return;
  for (const group of chunkArray(buffer, 10)) {
    await sqs.send(new SendMessageBatchCommand({
      QueueUrl: QUEUE_URL,
      Entries: group.map((msg, i) => ({ Id: String(i), MessageBody: JSON.stringify(msg) }))
    }));
  }
}

function makeResource(id, name, type, region, state, meta, tags, scanId) {
  return {
    id,
    name: name || id.split("/").pop() || id,
    type: type.toLowerCase(),
    provider: "aws",
    region: region || "global",
    state: state || "active",
    tags: tags || {},
    meta: { ...meta, ownerId: ACCOUNT_ID },
    scanId
  };
}

exports.handler = async () => {
  const scanId = new Date().toISOString();
  const buffer = [];
  let total = 0;

  const push = async (resource) => {
    buffer.push(resource);
    total++;
    if (buffer.length >= 100) {
      await flushToSqs(buffer.splice(0));
    }
  };

  // Resource Explorer covers: EC2, S3, RDS, Lambda, ECS, EKS, DynamoDB, SNS, SQS,
  // ElastiCache, Redshift, OpenSearch, Kinesis, Glue, Step Functions, EventBridge,
  // API Gateway, AppSync, Cognito, SageMaker, Bedrock, EMR, MSK, MQ, WAF, KMS,
  // SSM, CodeBuild, CodePipeline, CodeDeploy, AppRunner, Batch, EFS, FSx, Backup,
  // VPC, Subnets, Security Groups, Load Balancers, Auto Scaling, CloudWatch, etc.
  try {
    let nextToken = null;
    do {
      const { Resources = [], NextToken } = await explorer.send(new SearchCommand({
        QueryString: "*",
        MaxResults: 1000,
        NextToken: nextToken
      }));
      nextToken = NextToken;

      for (const r of Resources) {
        const region = r.Arn.split(":")[3] || "global";
        const tags = {};
        if (Array.isArray(r.Properties)) {
          for (const p of r.Properties) {
            if (p.Name === "tags" && Array.isArray(p.Data)) {
              for (const t of p.Data) tags[t.Key] = t.Value;
            }
          }
        }
        await push(makeResource(
          r.Arn,
          tags["Name"] || r.Arn.split("/").pop(),
          r.ResourceType,
          region,
          "active",
          { service: r.Service, lastQueried: r.LastQueriedAt },
          tags,
          scanId
        ));
      }
    } while (nextToken);
  } catch (e) {
    if (e.name === "ValidationException") {
      console.warn("Resource Explorer not enabled — running supplemental scans only.");
    } else {
      console.error("Resource Explorer error:", e.message);
    }
  }

  // IAM — not indexed by Resource Explorer
  try {
    let marker;
    do {
      const { Users = [], Marker } = await iam.send(new ListUsersCommand({ Marker: marker, MaxItems: 100 }));
      marker = Marker;
      for (const u of Users) {
        await push(makeResource(u.Arn, u.UserName, "iam::user", "global", "active", { createdAt: u.CreateDate }, {}, scanId));
      }
    } while (marker);

    let roleMarker;
    do {
      const { Roles = [], Marker } = await iam.send(new ListRolesCommand({ Marker: roleMarker, MaxItems: 100 }));
      roleMarker = Marker;
      for (const r of Roles) {
        if (r.Path.startsWith("/aws-service-role/")) continue;
        await push(makeResource(r.Arn, r.RoleName, "iam::role", "global", "active", { createdAt: r.CreateDate }, {}, scanId));
      }
    } while (roleMarker);

    let policyMarker;
    do {
      const { Policies = [], Marker } = await iam.send(new ListPoliciesCommand({ Scope: "Local", Marker: policyMarker, MaxItems: 100 }));
      policyMarker = Marker;
      for (const p of Policies) {
        await push(makeResource(p.Arn, p.PolicyName, "iam::policy", "global", "active", {}, {}, scanId));
      }
    } while (policyMarker);
  } catch (e) { console.error("IAM scan error:", e.message); }

  // Route53 — global, not in Resource Explorer
  try {
    let marker;
    do {
      const { HostedZones = [], NextMarker } = await route53.send(new ListHostedZonesCommand({ Marker: marker }));
      marker = NextMarker;
      for (const z of HostedZones) {
        await push(makeResource(
          z.Id, z.Name, "route53::hostedzone", "global", "active",
          { recordCount: z.ResourceRecordSetCount, private: z.Config?.PrivateZone },
          {}, scanId
        ));
      }
    } while (marker);
  } catch (e) { console.error("Route53 scan error:", e.message); }

  // CloudFront — global
  try {
    const { DistributionList } = await cloudfront.send(new ListDistributionsCommand({}));
    for (const d of DistributionList?.Items || []) {
      await push(makeResource(
        d.ARN, d.DomainName, "cloudfront::distribution", "global",
        d.Status?.toLowerCase() || "active",
        { origins: d.Origins?.Items?.map(o => o.DomainName).join(","), priceClass: d.PriceClass },
        {}, scanId
      ));
    }
  } catch (e) { console.error("CloudFront scan error:", e.message); }

  // ACM Certificates (us-east-1 = global certs)
  try {
    const { CertificateSummaryList = [] } = await acm.send(new ListCertificatesCommand({}));
    for (const c of CertificateSummaryList) {
      await push(makeResource(c.CertificateArn, c.DomainName, "acm::certificate", "us-east-1", c.Status?.toLowerCase() || "active", {}, {}, scanId));
    }
  } catch (e) { console.error("ACM scan error:", e.message); }

  // Secrets Manager
  try {
    let nextToken;
    do {
      const { SecretList = [], NextToken } = await secretsMgr.send(new ListSecretsCommand({ NextToken: nextToken, MaxResults: 100 }));
      nextToken = NextToken;
      for (const s of SecretList) {
        await push(makeResource(
          s.ARN, s.Name, "secretsmanager::secret",
          process.env.AWS_REGION || "us-east-1", "active",
          { rotationEnabled: s.RotationEnabled }, {}, scanId
        ));
      }
    } while (nextToken);
  } catch (e) { console.error("Secrets Manager scan error:", e.message); }

  if (buffer.length) await flushToSqs(buffer.splice(0));

  console.log(`Scan complete. Streamed ${total} resources. ScanId: ${scanId}`);
  return { statusCode: 200, body: JSON.stringify({ message: "Scan finished", resourcesFound: total, scanId }) };
};
