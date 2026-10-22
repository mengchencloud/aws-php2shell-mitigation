# PHP2Shell Mitigation on AWS (WAF CloudFormation + Patch Guide)

[中文](#中文) | [English](#english)

> 本项目不是 AWS 官方产品，内容以 AWS 安全公告和 PHP 官方为准。
> This is not an official AWS project. AWS security bulletins and php.net are authoritative.

---

## 中文

### 1. 漏洞概况
- **CVE-2026-109618**：内存耗尽时的内存损坏。**CVE-2026-109619**：上一个请求的残留状态被下一个请求复用。两个都是 CVSS v4 9.2 分，未登录就能远程执行代码，已经发现在野利用。
- 问题出在 PHP 解析 `multipart/form-data` 的阶段，业务代码还没运行就触发了，所以应用自己的登录校验挡不住。mod_php、PHP-FPM、php-cgi、FrankenPHP、LiteSpeed 都受影响。
- AWS 公告：[2026-143-AWS](https://aws.amazon.com/security/security-bulletins/rss/2026-143-aws/)。AWS 自身服务不受影响，在 AWS 上自行部署和管理的 PHP 需要处理。

| PHP 分支 | 修复版本 |
|---|---|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 8.1 及更老 | 没有正式修复，只能迁移到受支持版本 |

### 2. 临时防护：AWS WAF（本仓库模板 `php2shell-waf.yaml`）
WAF 只是打补丁前的纵深防护，官方明确说 WAF 和配置调整都不能完全防住。PHP 配置层面还可以设 `session.upload_progress.enabled=0`；8.5 版本再加 `fatal_error_backtraces=0`，然后重启 worker。

| 资源 | 什么时候建 | 作用 |
|---|---|---|
| 自定义 Rule Group（REGIONAL，50 WCU） | 总是建 | `PHP2Shell` 规则（防 109619，逻辑照搬 AWS 公告）：POST 请求，请求体里有 `PHP_SESSION_UPLOAD_PROGRESS`，并且 cookie 名或请求体里有 `PHPSESSID`。`BodySizeOver8KB` 规则（防 109618）：请求体超过 8KB，逻辑同 CRS 的 `SizeRestrictions_BODY` |
| 新 Web ACL | `CreateWebACL=true` | 引用上面的 Rule Group，可选加 `AWSManagedRulesPHPRuleSet`（固定 `Version_2.3`，带 `PHP2Shell_BODY`）和 `AWSManagedRulesCommonRuleSet` |
| Web ACL 关联 | `CreateWebACL=true` 且填了 `AssociateResourceArn` | 把新 Web ACL 挂到 ALB 或 API Gateway stage |

**怎么选**
- **已经有 WAF**：保持 `CreateWebACL=false`，只建 Rule Group。然后在现有 Web ACL 里加一条规则，引用输出的 `RuleGroupArn`，优先级放在最前面。
- **还没有 WAF**：设 `CreateWebACL=true`，并填 `AssociateResourceArn`。注意一个资源只能挂一个 Web ACL，如果资源已经挂了，会被替换掉。

**部署命令**
```bash
# 校验模板
aws cloudformation validate-template --region cn-northwest-1 \
  --template-body file://php2shell-waf.yaml

# 已有 WAF：只建 Rule Group
aws cloudformation deploy --region cn-northwest-1 \
  --stack-name php2shell-waf --template-file php2shell-waf.yaml

# 没有 WAF：新建 Web ACL，并挂到 ALB
aws cloudformation deploy --region cn-north-1 \
  --stack-name php2shell-waf --template-file php2shell-waf.yaml \
  --parameter-overrides CreateWebACL=true AssociateResourceArn=<ALB ARN>

# 查看输出（RuleGroupArn / WebACLArn）
aws cloudformation describe-stacks --region cn-northwest-1 \
  --stack-name php2shell-waf --query "Stacks[0].Outputs"

# 回滚
aws cloudformation delete-stack --region cn-northwest-1 --stack-name php2shell-waf
```
PowerShell 下把行尾的 `\` 换成反引号 `` ` ``，或者把命令写成一行。

**参数**

| 参数 | 默认值 | 说明 |
|---|---|---|
| `NamePrefix` | `php2shell` | 资源名和指标名前缀 |
| `RuleAction` | `Count` | 所有规则的统一开关。`Count`：只计数不拦截，先在 CloudWatch 指标和采样请求里确认没有误报；`Block`：自定义规则直接拦截，PHP 托管规则组和 CRS 按规则自身的动作执行（基本是 Block） |
| `IncludeBodySizeRule` | `true` | 是否加 8KB 规则（防 109618）。Block 模式下会误伤超过 8KB 的文件上传。已经开了 CRS `SizeRestrictions_BODY` 的，设成 `false` |
| `CreateWebACL` | `false` | 是否新建 Web ACL |
| `IncludePHPManagedRuleGroup` | `true` | 新 Web ACL 里加 PHP 托管规则组（100 WCU） |
| `PHPManagedRuleGroupVersion` | `Version_2.3` | 默认版本可能还是 2.2（没有 `PHP2Shell_BODY`），所以要显式指定 |
| `IncludeCoreRuleSet` | `false` | 新 Web ACL 里加 CRS（700 WCU） |
| `AssociateResourceArn` | 空 | 要关联的 ALB 或 API Gateway stage ARN |

**从 Count 切到 Block**：观察确认没有误报后，用同一个 stack 名再部署一次，加上 `RuleAction=Block`，其他参数保持不变：
```bash
aws cloudformation deploy --region cn-northwest-1 \
  --stack-name php2shell-waf --template-file php2shell-waf.yaml \
  --parameter-overrides CreateWebACL=true RuleAction=Block
```
想退回观察模式，再改回 `RuleAction=Count` 部署即可。

**注意事项**
1. **中国区（cn-north-1 / cn-northwest-1）的 WAF 不能挂 CloudFront**，只能挂区域资源。CloudFront + ALB 架构，就挂在源站 ALB 上。本模板在北京和宁夏都校验过。
2. **ALB 只检查请求体前 8KB**。`PHP2Shell` 规则用的是 `OversizeHandling: CONTINUE`，攻击者可以把字段放到 8KB 之后来绕过。所以要配合 `BodySizeOver8KB`（或 CRS `SizeRestrictions_BODY`）一起用。
3. 默认是 Count，部署后不会拦截任何请求。确认没有误报后再切到 Block，否则只有观察作用，没有防护作用。
4. Rule Group 的容量（Capacity）建好后不能改，要改只能替换资源。
5. 全球区的 CloudFront（`CLOUDFRONT` scope，部署在 us-east-1）不在本模板范围内。

### 3. 修复方法（按运行环境）

> 通用要求：升级后**必须重启** php-fpm、httpd 或应用进程。旧进程不重启，还在跑漏洞版本。

**EC2：Amazon Linux 2023**（公告 ALAS2023-2026-3301 ~ 3304）
```bash
rpm -qa | grep -i '^php'                        # 看装的是哪个分支
sudo dnf upgrade --releasever=latest 'php8.*'
sudo systemctl restart php-fpm httpd            # 按实际服务名
php -v
```
AL2023 的 php8.1 没有修复，需要迁移到 php8.2 及以上。

**EC2：Amazon Linux 2**
```bash
sudo yum update --advisory ALAS2PHP8.2-2026-015  # Extras 的 php8.2 -> 8.2.35
sudo systemctl restart php-fpm httpd
```
AL2 核心仓库自带的 php 5.4 没有修复，需要迁移。

**EC2：Ubuntu / Debian / RHEL 等**：用发行版的安全更新，例如 Ubuntu 上：
```bash
sudo apt update
apt list --upgradable | grep php
sudo apt install --only-upgrade 'php8.*'
sudo systemctl restart php8.3-fpm apache2
```
具体修复包版本以各发行版的安全公告为准。

**Elastic Beanstalk**：PHP 平台 v4.13.12 已修复这两个漏洞。开了托管平台更新的环境会在维护窗口自动升级；没开的，在控制台或用 `aws elasticbeanstalk update-environment --solution-stack-name ...` 手动更新到最新 PHP 平台版本。

**Lightsail**（LAMP、WordPress 等蓝图）：已经在跑的实例没法原地更新，只能用新蓝图建实例，再把应用迁过去。

**ECS / EKS / 自建容器镜像**：把基础镜像换成修复版本（例如官方 `php:8.3.36-fpm` 之类的 tag），重新构建、推送，再滚动更新服务。可以用 Inspector 的 ECR 扫描确认没有旧镜像还在用。

**Lambda**：Lambda 没有托管的 PHP 运行时。PHP 一般跑在自定义运行时（`provided.al2` 或 `provided.al2023` 加 Bref 之类的 layer）或者容器镜像里：
- 用 layer 的：升级到 PHP 版本已修复的 layer，重新部署函数，并确认函数配置引用的是新 layer 版本的 ARN。
- 用容器镜像的：换成修复版本的基础镜像，重新构建，再执行 `aws lambda update-function-code --image-uri ...`。
- 查哪些函数用了自定义运行时：`aws lambda list-functions --query "Functions[?starts_with(Runtime||'', 'provided')].[FunctionName,Runtime]"`。容器镜像函数的 Runtime 是空的，要看 `PackageType=Image`。

**Amazon WorkMail**：由 AWS 处理，无需任何操作。

### 4. 怎么查受影响范围
- **Amazon Inspector**：漏洞库更新后，会自动标出 EC2、ECR、Lambda 上没修复的 PHP。在规则覆盖到你的操作系统之前，搜 CVE 返回 0 条，不代表没受影响。
- **Security Hub**：本身不扫描，只汇总 Inspector 的结果，适合跨账号按 CVE 编号过滤。
- **SSM Inventory**：在 Systems Manager 的 Inventory 里按应用名 `php` 过滤，不用登录机器就能看到装了 PHP 的实例和版本。
- **入口暴露面**：检查对外的 ALB 和 API Gateway 有没有挂 WAF，没挂的优先用第 2 节的模板。

---

## English

### 1. Overview
- **CVE-2026-109618**: memory corruption under memory exhaustion. **CVE-2026-109619**: request state from a previous request reused by the next one. Both CVSS v4 9.2, unauthenticated RCE, exploited in the wild.
- Triggered while PHP parses `multipart/form-data`, before any application code runs, so application-level auth does not help. Affects mod_php, PHP-FPM, php-cgi, FrankenPHP and LiteSpeed.
- AWS bulletin: [2026-143-AWS](https://aws.amazon.com/security/security-bulletins/rss/2026-143-aws/). AWS services are not affected; self-managed PHP running on AWS must be remediated.

| PHP branch | Fixed version |
|---|---|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 8.1 and older | No official fix - migrate to a supported branch |

### 2. Temporary mitigation - AWS WAF (`php2shell-waf.yaml`)
WAF is defense in depth until you patch; AWS states that neither WAF nor config changes fully prevent exploitation. On the PHP side you can also set `session.upload_progress.enabled=0` (and `fatal_error_backtraces=0` on 8.5), then restart workers.

| Resource | When | Purpose |
|---|---|---|
| Custom rule group (REGIONAL, 50 WCU) | Always | `PHP2Shell` (109619, logic from the AWS bulletin): POST with `PHP_SESSION_UPLOAD_PROGRESS` in the body AND `PHPSESSID` as a cookie name or in the body. `BodySizeOver8KB` (109618): body larger than 8 KB, same as CRS `SizeRestrictions_BODY` |
| New Web ACL | `CreateWebACL=true` | References the rule group, optionally adds `AWSManagedRulesPHPRuleSet` (pinned to `Version_2.3`, includes `PHP2Shell_BODY`) and `AWSManagedRulesCommonRuleSet` |
| Web ACL association | `CreateWebACL=true` and `AssociateResourceArn` set | Attaches the new Web ACL to an ALB or API Gateway stage |

**Which mode**
- **Existing WAF**: keep `CreateWebACL=false` and reference the `RuleGroupArn` output from your existing Web ACL at the highest priority.
- **No WAF**: set `CreateWebACL=true` and `AssociateResourceArn`. A resource can have only one Web ACL; an existing association would be replaced.

**Commands**
```bash
aws cloudformation validate-template --region cn-northwest-1 \
  --template-body file://php2shell-waf.yaml

# Existing WAF: rule group only
aws cloudformation deploy --region cn-northwest-1 \
  --stack-name php2shell-waf --template-file php2shell-waf.yaml

# No WAF: create a Web ACL and attach it to an ALB
aws cloudformation deploy --region cn-north-1 \
  --stack-name php2shell-waf --template-file php2shell-waf.yaml \
  --parameter-overrides CreateWebACL=true AssociateResourceArn=<ALB ARN>

aws cloudformation describe-stacks --region cn-northwest-1 \
  --stack-name php2shell-waf --query "Stacks[0].Outputs"

# Rollback
aws cloudformation delete-stack --region cn-northwest-1 --stack-name php2shell-waf
```
In PowerShell replace the trailing `\` with a backtick or put each command on one line.

**Parameters**

| Parameter | Default | Notes |
|---|---|---|
| `NamePrefix` | `php2shell` | Prefix for resource and metric names |
| `RuleAction` | `Count` | One switch for all rules. `Count`: count only, nothing blocked - check CloudWatch metrics and sampled requests first. `Block`: custom rules block; the PHP managed group and CRS use their own rule actions (mostly Block) |
| `IncludeBodySizeRule` | `true` | Add the 8 KB rule (109618). In Block mode it hits uploads larger than 8 KB. Set `false` if CRS `SizeRestrictions_BODY` is already on |
| `CreateWebACL` | `false` | Create a new Web ACL |
| `IncludePHPManagedRuleGroup` | `true` | Add the PHP managed rule group (100 WCU) |
| `PHPManagedRuleGroupVersion` | `Version_2.3` | The default may still be 2.2 (no `PHP2Shell_BODY`), so pin it |
| `IncludeCoreRuleSet` | `false` | Add CRS (700 WCU) |
| `AssociateResourceArn` | empty | ALB or API Gateway stage ARN to associate |

**Switching from Count to Block**: once no false positives are seen, redeploy the same stack with `RuleAction=Block` and the other parameters unchanged:
```bash
aws cloudformation deploy --region cn-northwest-1 \
  --stack-name php2shell-waf --template-file php2shell-waf.yaml \
  --parameter-overrides CreateWebACL=true RuleAction=Block
```
Redeploy with `RuleAction=Count` to go back to observe-only.

**Notes**
1. **In AWS China regions (cn-north-1 / cn-northwest-1) WAF cannot be attached to CloudFront**, only to regional resources. For CloudFront + ALB, attach it to the origin ALB. Validated in Beijing and Ningxia.
2. **ALB inspects only the first 8 KB of the body.** `PHP2Shell` uses `OversizeHandling: CONTINUE`, so a payload placed after 8 KB can bypass it. Pair it with `BodySizeOver8KB` (or CRS `SizeRestrictions_BODY`).
3. The default is Count, so nothing is blocked after deployment. Switch to Block once validated; Count alone only observes and does not protect.
4. Rule group capacity is immutable; changing it replaces the resource.
5. Global CloudFront (`CLOUDFRONT` scope in us-east-1) is out of scope.

### 3. Remediation by platform

> Always **restart** php-fpm / httpd / your app process after upgrading; old workers keep running the vulnerable binary.

**EC2 - Amazon Linux 2023** (ALAS2023-2026-3301 ~ 3304)
```bash
rpm -qa | grep -i '^php'
sudo dnf upgrade --releasever=latest 'php8.*'
sudo systemctl restart php-fpm httpd
php -v
```
php8.1 on AL2023 has no fix - migrate to php8.2+.

**EC2 - Amazon Linux 2**
```bash
sudo yum update --advisory ALAS2PHP8.2-2026-015   # Extras php8.2 -> 8.2.35
sudo systemctl restart php-fpm httpd
```
The core AL2 php 5.4 has no fix - migrate.

**EC2 - Ubuntu / Debian / RHEL, etc.**: apply your distribution's security update, e.g. on Ubuntu:
```bash
sudo apt update
apt list --upgradable | grep php
sudo apt install --only-upgrade 'php8.*'
sudo systemctl restart php8.3-fpm apache2
```
Check your distribution's security advisory for the exact fixed package version.

**Elastic Beanstalk**: PHP platform v4.13.12 fixes both CVEs. Environments with managed platform updates upgrade in their maintenance window; otherwise update the platform version in the console or with `aws elasticbeanstalk update-environment --solution-stack-name ...`.

**Lightsail** (LAMP / WordPress blueprints): running instances cannot be updated in place - create a new instance from the latest blueprint and migrate.

**ECS / EKS / custom container images**: move to a fixed base image (e.g. `php:8.3.36-fpm`), rebuild, push and roll the service. Use Inspector ECR scanning to find images still in use with old PHP.

**Lambda**: Lambda has no managed PHP runtime; PHP runs on a custom runtime (`provided.al2` / `provided.al2023` with a layer such as Bref) or a container image.
- Layer-based: upgrade to a layer version that ships a fixed PHP, redeploy, and confirm the function references the new layer version ARN.
- Container image: rebuild on a fixed base image and run `aws lambda update-function-code --image-uri ...`.
- Find custom-runtime functions: `aws lambda list-functions --query "Functions[?starts_with(Runtime||'', 'provided')].[FunctionName,Runtime]"`; image functions have `PackageType=Image` and no Runtime.

**Amazon WorkMail**: handled by AWS, no action needed.

### 4. Finding affected resources
- **Amazon Inspector** flags unpatched PHP on EC2, ECR and Lambda once its vulnerability database covers your OS. Zero findings before coverage lands does not mean you are safe.
- **Security Hub** only aggregates Inspector findings; filter by CVE ID across accounts.
- **SSM Inventory**: filter applications by name `php` in Systems Manager Inventory to list instances and versions without logging in.
- **Exposure**: check whether internet-facing ALBs / API Gateways have a Web ACL. Those without one are the first candidates for the template in section 2.

## License

MIT-0. See [LICENSE](LICENSE).
