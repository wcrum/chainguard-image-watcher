# Chain Guard Severity Stats
Someone sent me a news article about Chainguard, looks great... a little too great in my opinion.

The website says `Reach 'inbox zero' for your CVEs` with content that makes you think that all Chainguard images have **zero** CVEs.

Well although, Chainguard has a lot less, zero vulnerabilities is pretty impossible.

So I scraped all images hosted in `cgr.dev`, then I scanned all of them since it didnt seem like they had any way to collect info at scale.

# Files
In `/results` you will find a ton of `.pkl` files, these are pickled scans from [pygrype](https://github.com/willyw0nka/pygrype). Probably should do this in a better way, I wrote this at like 1am.

`scan.py` is the primary file, it reaches out to `https://console-api.enforce.dev/query` to get all the content / list of images you need.

# Results

> [!CAUTION]
> Counts total CVE by severity for image, then adds it. Does not check if CVE is unique.

| Severity | Total |
| -- | -- |
| Critical | 0 |
| High | 38 |
| Medium | 78 |
| Low | 5 |
| Unknown | 41 |
| Negligible | 0 |

| Image | Criticals | Highs | Mediums | Lows | Unknown | Negligble |
| -- | -- | -- | -- | -- | -- | -- |
| [cgr.dev/chainguard/gitness:latest](cgr.dev/chainguard/gitness:latest) |  |  | [GHSA-9w9f-6mg8-jp7w](https://github.com/advisories/GHSA-9w9f-6mg8-jp7w) |  |  |  |
| [cgr.dev/chainguard/confluent-kafka:latest](cgr.dev/chainguard/confluent-kafka:latest) |  |  | [GHSA-6qvw-249j-h44c](https://github.com/advisories/GHSA-6qvw-249j-h44c),[GHSA-r978-9m6m-6gm6](https://github.com/advisories/GHSA-r978-9m6m-6gm6) |  |  |  |
| [cgr.dev/chainguard/terraform:latest](cgr.dev/chainguard/terraform:latest) |  |  | [GHSA-8r3f-844c-mc37](https://github.com/advisories/GHSA-8r3f-844c-mc37) |  | [CVE-2023-45288](https://go.dev/cl/576155) |  |
| [cgr.dev/chainguard/opensearch:latest](cgr.dev/chainguard/opensearch:latest) |  |  | [GHSA-5jpm-x58v-624v](https://github.com/advisories/GHSA-5jpm-x58v-624v),[GHSA-5jpm-x58v-624v](https://github.com/advisories/GHSA-5jpm-x58v-624v),[GHSA-5jpm-x58v-624v](https://github.com/advisories/GHSA-5jpm-x58v-624v) |  |  |  |
| [cgr.dev/chainguard/external-secrets:latest](cgr.dev/chainguard/external-secrets:latest) |  |  |  |  | [CVE-2023-45288](https://go.dev/cl/576155) |  |
| [cgr.dev/chainguard/ruby:latest](cgr.dev/chainguard/ruby:latest) |  | [GHSA-592j-995h-p23j](https://github.com/advisories/GHSA-592j-995h-p23j) |  |  |  |  |
| [cgr.dev/chainguard/fluentd:latest](cgr.dev/chainguard/fluentd:latest) |  | [GHSA-592j-995h-p23j](https://github.com/advisories/GHSA-592j-995h-p23j) |  |  |  |  |
| [cgr.dev/chainguard/wavefront-proxy:latest](cgr.dev/chainguard/wavefront-proxy:latest) |  |  | [GHSA-5jpm-x58v-624v](https://github.com/advisories/GHSA-5jpm-x58v-624v),[GHSA-w33c-445m-f8w7](https://github.com/advisories/GHSA-w33c-445m-f8w7) |  |  |  |
| [cgr.dev/chainguard/kube-logging-operator-fluentd:latest](cgr.dev/chainguard/kube-logging-operator-fluentd:latest) |  | [GHSA-592j-995h-p23j](https://github.com/advisories/GHSA-592j-995h-p23j) |  |  |  |  |
| [cgr.dev/chainguard/gitness](cgr.dev/chainguard/gitness) |  |  | [GHSA-9w9f-6mg8-jp7w](https://github.com/advisories/GHSA-9w9f-6mg8-jp7w) |  |  |  |
| [cgr.dev/chainguard/busybox:latest](cgr.dev/chainguard/busybox:latest) |  |  | [CVE-2023-42365](https://bugs.busybox.net/show_bug.cgi?id=15871),[CVE-2023-42364](https://bugs.busybox.net/show_bug.cgi?id=15868),[CVE-2023-42363](https://bugs.busybox.net/show_bug.cgi?id=15865),[CVE-2023-42365](https://bugs.busybox.net/show_bug.cgi?id=15871),[CVE-2023-42364](https://bugs.busybox.net/show_bug.cgi?id=15868),[CVE-2023-42363](https://bugs.busybox.net/show_bug.cgi?id=15865) |  |  |  |
| [cgr.dev/chainguard/vault:latest](cgr.dev/chainguard/vault:latest) |  |  | [GHSA-j2rp-gmqv-frhv](https://github.com/advisories/GHSA-j2rp-gmqv-frhv),[GHSA-rhh4-rh7c-7r5v](https://github.com/advisories/GHSA-rhh4-rh7c-7r5v) |  | [CVE-2023-45288](https://go.dev/cl/576155) |  |
| [cgr.dev/chainguard/keycloak:latest](cgr.dev/chainguard/keycloak:latest) |  | [GHSA-f8h5-v2vg-46rr](https://github.com/advisories/GHSA-f8h5-v2vg-46rr) |  |  |  |  |
| [cgr.dev/chainguard/harbor-registry:latest](cgr.dev/chainguard/harbor-registry:latest) |  |  |  |  | [CVE-2023-45288](https://go.dev/cl/576155) |  |
| [cgr.dev/chainguard/logstash-oss-with-opensearch-output-plugin:latest](cgr.dev/chainguard/logstash-oss-with-opensearch-output-plugin:latest) |  | [GHSA-592j-995h-p23j](https://github.com/advisories/GHSA-592j-995h-p23j),[GHSA-592j-995h-p23j](https://github.com/advisories/GHSA-592j-995h-p23j) | [GHSA-5jpm-x58v-624v](https://github.com/advisories/GHSA-5jpm-x58v-624v),[GHSA-5jpm-x58v-624v](https://github.com/advisories/GHSA-5jpm-x58v-624v),[GHSA-hww2-5g85-429m](https://github.com/advisories/GHSA-hww2-5g85-429m),[GHSA-hww2-5g85-429m](https://github.com/advisories/GHSA-hww2-5g85-429m) |  |  |  |
| [cgr.dev/chainguard/haproxy-ingress:latest](cgr.dev/chainguard/haproxy-ingress:latest) |  |  | [GHSA-8r3f-844c-mc37](https://github.com/advisories/GHSA-8r3f-844c-mc37) |  | [GHSA-8r3f-844c-mc37](https://github.com/advisories/GHSA-8r3f-844c-mc37),[CVE-2024-24786](https://www.cve.org/CVERecord?id=CVE-2024-24786),[GHSA-8r3f-844c-mc37](https://github.com/advisories/GHSA-8r3f-844c-mc37),[CVE-2024-24786](https://www.cve.org/CVERecord?id=CVE-2024-24786),[CVE-2023-45288](https://go.dev/cl/576155) |  |
| [cgr.dev/chainguard/kubeflow-centraldashboard:latest](cgr.dev/chainguard/kubeflow-centraldashboard:latest) |  | [GHSA-mxhp-79qh-mcx6](https://github.com/advisories/GHSA-mxhp-79qh-mcx6) | [GHSA-rv95-896h-c2vc](https://github.com/advisories/GHSA-rv95-896h-c2vc),[GHSA-cxjh-pqwp-8mfp](https://github.com/advisories/GHSA-cxjh-pqwp-8mfp),[CVE-2024-29041](https://www.cve.org/CVERecord?id=CVE-2024-29041),[CVE-2024-28849](https://www.cve.org/CVERecord?id=CVE-2024-28849),[CVE-2024-28182](https://github.com/nghttp2/nghttp2/commit/00201ecd8f982da3b67d4f6868af72a1b03b14e0),[GHSA-p8p7-x288-28g6](https://github.com/advisories/GHSA-p8p7-x288-28g6),[GHSA-f5x3-32g6-xq36](https://github.com/advisories/GHSA-f5x3-32g6-xq36) |  | [GHSA-rv95-896h-c2vc](https://github.com/advisories/GHSA-rv95-896h-c2vc),[GHSA-cxjh-pqwp-8mfp](https://github.com/advisories/GHSA-cxjh-pqwp-8mfp) |  |
| [cgr.dev/chainguard/helm-operator:latest](cgr.dev/chainguard/helm-operator:latest) |  |  |  |  | [CVE-2023-45288](https://go.dev/cl/576155) |  |
| [cgr.dev/chainguard/opensearch-dashboards:latest](cgr.dev/chainguard/opensearch-dashboards:latest) |  | [GHSA-c429-5p7v-vgjp](https://github.com/advisories/GHSA-c429-5p7v-vgjp) | [GHSA-cxjh-pqwp-8mfp](https://github.com/advisories/GHSA-cxjh-pqwp-8mfp),[CVE-2024-28182](https://github.com/nghttp2/nghttp2/commit/00201ecd8f982da3b67d4f6868af72a1b03b14e0),[GHSA-f5x3-32g6-xq36](https://github.com/advisories/GHSA-f5x3-32g6-xq36),[GHSA-f5x3-32g6-xq36](https://github.com/advisories/GHSA-f5x3-32g6-xq36) |  |  |  |
| [cgr.dev/chainguard/sqlpad:latest](cgr.dev/chainguard/sqlpad:latest) |  | [GHSA-5pgg-2g8v-p4x9](https://github.com/advisories/GHSA-5pgg-2g8v-p4x9) | [GHSA-rv95-896h-c2vc](https://github.com/advisories/GHSA-rv95-896h-c2vc),[GHSA-f5x3-32g6-xq36](https://github.com/advisories/GHSA-f5x3-32g6-xq36) |  |  |  |
| [cgr.dev/chainguard/datadog-agent:latest](cgr.dev/chainguard/datadog-agent:latest) |  |  | [GHSA-rhh4-rh7c-7r5v](https://github.com/advisories/GHSA-rhh4-rh7c-7r5v) |  |  |  |
| [cgr.dev/chainguard/trino:latest](cgr.dev/chainguard/trino:latest) |  |  | [GHSA-5jpm-x58v-624v](https://github.com/advisories/GHSA-5jpm-x58v-624v) |  |  |  |
| [cgr.dev/chainguard/kube-fluentd-operator:latest](cgr.dev/chainguard/kube-fluentd-operator:latest) |  | [GHSA-592j-995h-p23j](https://github.com/advisories/GHSA-592j-995h-p23j) | [GHSA-8r3f-844c-mc37](https://github.com/advisories/GHSA-8r3f-844c-mc37),[GHSA-c8v6-786g-vjx6](https://github.com/advisories/GHSA-c8v6-786g-vjx6),[CVE-2024-26146](https://www.cve.org/CVERecord?id=CVE-2024-26146),[CVE-2024-26141](https://www.cve.org/CVERecord?id=CVE-2024-26141),[CVE-2024-25126](https://www.cve.org/CVERecord?id=CVE-2024-25126),[CVE-2024-26146](https://www.cve.org/CVERecord?id=CVE-2024-26146),[CVE-2024-26141](https://www.cve.org/CVERecord?id=CVE-2024-26141),[CVE-2024-25126](https://www.cve.org/CVERecord?id=CVE-2024-25126),[CVE-2024-26146](https://www.cve.org/CVERecord?id=CVE-2024-26146),[CVE-2024-26141](https://www.cve.org/CVERecord?id=CVE-2024-26141),[CVE-2024-25126](https://www.cve.org/CVERecord?id=CVE-2024-25126),[CVE-2024-26146](https://www.cve.org/CVERecord?id=CVE-2024-26146),[CVE-2024-26141](https://www.cve.org/CVERecord?id=CVE-2024-26141),[CVE-2024-25126](https://www.cve.org/CVERecord?id=CVE-2024-25126) | [GHSA-xj5v-6v4g-jfw6](https://github.com/advisories/GHSA-xj5v-6v4g-jfw6),[GHSA-54rr-7fvw-6x8f](https://github.com/advisories/GHSA-54rr-7fvw-6x8f),[GHSA-22f2-v57c-j9cx](https://github.com/advisories/GHSA-22f2-v57c-j9cx) | [GHSA-xj5v-6v4g-jfw6](https://github.com/advisories/GHSA-xj5v-6v4g-jfw6),[GHSA-c8v6-786g-vjx6](https://github.com/advisories/GHSA-c8v6-786g-vjx6),[GHSA-8r3f-844c-mc37](https://github.com/advisories/GHSA-8r3f-844c-mc37),[GHSA-54rr-7fvw-6x8f](https://github.com/advisories/GHSA-54rr-7fvw-6x8f),[GHSA-22f2-v57c-j9cx](https://github.com/advisories/GHSA-22f2-v57c-j9cx),[CVE-2024-24786](https://www.cve.org/CVERecord?id=CVE-2024-24786),[CVE-2023-51774](https://www.cve.org/CVERecord?id=CVE-2023-51774),[GHSA-xj5v-6v4g-jfw6](https://github.com/advisories/GHSA-xj5v-6v4g-jfw6),[GHSA-c8v6-786g-vjx6](https://github.com/advisories/GHSA-c8v6-786g-vjx6),[GHSA-8r3f-844c-mc37](https://github.com/advisories/GHSA-8r3f-844c-mc37),[GHSA-54rr-7fvw-6x8f](https://github.com/advisories/GHSA-54rr-7fvw-6x8f),[GHSA-22f2-v57c-j9cx](https://github.com/advisories/GHSA-22f2-v57c-j9cx),[CVE-2024-24786](https://www.cve.org/CVERecord?id=CVE-2024-24786),[CVE-2023-51774](https://www.cve.org/CVERecord?id=CVE-2023-51774),[GHSA-xj5v-6v4g-jfw6](https://github.com/advisories/GHSA-xj5v-6v4g-jfw6),[GHSA-c8v6-786g-vjx6](https://github.com/advisories/GHSA-c8v6-786g-vjx6),[GHSA-8r3f-844c-mc37](https://github.com/advisories/GHSA-8r3f-844c-mc37),[GHSA-54rr-7fvw-6x8f](https://github.com/advisories/GHSA-54rr-7fvw-6x8f),[GHSA-22f2-v57c-j9cx](https://github.com/advisories/GHSA-22f2-v57c-j9cx),[CVE-2024-24786](https://www.cve.org/CVERecord?id=CVE-2024-24786),[CVE-2023-51774](https://www.cve.org/CVERecord?id=CVE-2023-51774),[GHSA-xj5v-6v4g-jfw6](https://github.com/advisories/GHSA-xj5v-6v4g-jfw6),[GHSA-c8v6-786g-vjx6](https://github.com/advisories/GHSA-c8v6-786g-vjx6),[GHSA-8r3f-844c-mc37](https://github.com/advisories/GHSA-8r3f-844c-mc37),[GHSA-54rr-7fvw-6x8f](https://github.com/advisories/GHSA-54rr-7fvw-6x8f),[GHSA-22f2-v57c-j9cx](https://github.com/advisories/GHSA-22f2-v57c-j9cx),[CVE-2024-24786](https://www.cve.org/CVERecord?id=CVE-2024-24786),[CVE-2023-51774](https://www.cve.org/CVERecord?id=CVE-2023-51774),[CVE-2023-45288](https://go.dev/cl/576155) |  |
| [cgr.dev/chainguard/temporal-server:latest](cgr.dev/chainguard/temporal-server:latest) |  | [GHSA-8pgv-569h-w5rw](https://github.com/advisories/GHSA-8pgv-569h-w5rw),[GHSA-8pgv-569h-w5rw](https://github.com/advisories/GHSA-8pgv-569h-w5rw) | [GHSA-8f25-w7qj-r7hc](https://github.com/advisories/GHSA-8f25-w7qj-r7hc) |  |  |  |
| [cgr.dev/chainguard/go-ipfs:latest](cgr.dev/chainguard/go-ipfs:latest) |  | [GHSA-c33x-xqrf-c478](https://github.com/advisories/GHSA-c33x-xqrf-c478) |  |  |  |  |
| [cgr.dev/chainguard/prometheus-cloudwatch-exporter:latest](cgr.dev/chainguard/prometheus-cloudwatch-exporter:latest) |  |  | [GHSA-5jpm-x58v-624v](https://github.com/advisories/GHSA-5jpm-x58v-624v) |  |  |  |
| [cgr.dev/chainguard/temporal-admin-tools:latest](cgr.dev/chainguard/temporal-admin-tools:latest) |  | [GHSA-8pgv-569h-w5rw](https://github.com/advisories/GHSA-8pgv-569h-w5rw),[GHSA-8pgv-569h-w5rw](https://github.com/advisories/GHSA-8pgv-569h-w5rw) | [GHSA-8f25-w7qj-r7hc](https://github.com/advisories/GHSA-8f25-w7qj-r7hc) |  |  |  |
| [cgr.dev/chainguard/management-api-for-apache-cassandra:latest](cgr.dev/chainguard/management-api-for-apache-cassandra:latest) |  | [GHSA-rgv9-q543-rqg4](https://github.com/advisories/GHSA-rgv9-q543-rqg4),[GHSA-jjjh-jjxp-wpff](https://github.com/advisories/GHSA-jjjh-jjxp-wpff),[GHSA-57j2-w4cx-62h2](https://github.com/advisories/GHSA-57j2-w4cx-62h2),[GHSA-3x8x-79m2-3w2w](https://github.com/advisories/GHSA-3x8x-79m2-3w2w),[GHSA-mjmj-j48q-9wg2](https://github.com/advisories/GHSA-mjmj-j48q-9wg2),[GHSA-3mc7-4q67-w48m](https://github.com/advisories/GHSA-3mc7-4q67-w48m),[GHSA-mjmj-j48q-9wg2](https://github.com/advisories/GHSA-mjmj-j48q-9wg2) | [GHSA-5jpm-x58v-624v](https://github.com/advisories/GHSA-5jpm-x58v-624v),[GHSA-5jpm-x58v-624v](https://github.com/advisories/GHSA-5jpm-x58v-624v),[GHSA-w37g-rhq8-7m4j](https://github.com/advisories/GHSA-w37g-rhq8-7m4j),[GHSA-hhhw-99gj-p3c3](https://github.com/advisories/GHSA-hhhw-99gj-p3c3),[GHSA-c4r9-r8fh-9vj2](https://github.com/advisories/GHSA-c4r9-r8fh-9vj2),[GHSA-9w3m-gqgf-c4p9](https://github.com/advisories/GHSA-9w3m-gqgf-c4p9),[GHSA-98wm-3w3q-mw94](https://github.com/advisories/GHSA-98wm-3w3q-mw94) |  |  |  |
| [cgr.dev/chainguard/git:latest](cgr.dev/chainguard/git:latest) |  |  | [CVE-2023-42365](https://bugs.busybox.net/show_bug.cgi?id=15871),[CVE-2023-42364](https://bugs.busybox.net/show_bug.cgi?id=15868),[CVE-2023-42363](https://bugs.busybox.net/show_bug.cgi?id=15865),[CVE-2023-42365](https://bugs.busybox.net/show_bug.cgi?id=15871),[CVE-2023-42364](https://bugs.busybox.net/show_bug.cgi?id=15868),[CVE-2023-42363](https://bugs.busybox.net/show_bug.cgi?id=15865),[CVE-2023-42365](https://bugs.busybox.net/show_bug.cgi?id=15871),[CVE-2023-42364](https://bugs.busybox.net/show_bug.cgi?id=15868),[CVE-2023-42363](https://bugs.busybox.net/show_bug.cgi?id=15865) |  |  |  |
| [cgr.dev/chainguard/spark-operator:latest](cgr.dev/chainguard/spark-operator:latest) |  | [GHSA-rhrv-645h-fjfh](https://github.com/advisories/GHSA-rhrv-645h-fjfh),[GHSA-4g9r-vxhx-9pgx](https://github.com/advisories/GHSA-4g9r-vxhx-9pgx),[GHSA-4265-ccf5-phj5](https://github.com/advisories/GHSA-4265-ccf5-phj5),[GHSA-fg2v-w576-w4v3](https://github.com/advisories/GHSA-fg2v-w576-w4v3),[GHSA-493p-pfq6-5258](https://github.com/advisories/GHSA-493p-pfq6-5258),[GHSA-rj7p-rfgp-852x](https://github.com/advisories/GHSA-rj7p-rfgp-852x),[GHSA-g2fg-mr77-6vrm](https://github.com/advisories/GHSA-g2fg-mr77-6vrm),[GHSA-95q3-pppp-r683](https://github.com/advisories/GHSA-95q3-pppp-r683),[GHSA-wrvw-hg22-4m67](https://github.com/advisories/GHSA-wrvw-hg22-4m67),[GHSA-g5ww-5jh7-63cx](https://github.com/advisories/GHSA-g5ww-5jh7-63cx),[GHSA-77rm-9x9h-xj3g](https://github.com/advisories/GHSA-77rm-9x9h-xj3g),[GHSA-4gg5-vx3j-xwc7](https://github.com/advisories/GHSA-4gg5-vx3j-xwc7),[GHSA-wrvw-hg22-4m67](https://github.com/advisories/GHSA-wrvw-hg22-4m67),[GHSA-g5ww-5jh7-63cx](https://github.com/advisories/GHSA-g5ww-5jh7-63cx),[GHSA-77rm-9x9h-xj3g](https://github.com/advisories/GHSA-77rm-9x9h-xj3g),[GHSA-4gg5-vx3j-xwc7](https://github.com/advisories/GHSA-4gg5-vx3j-xwc7) | [GHSA-xjp4-hw94-mvp5](https://github.com/advisories/GHSA-xjp4-hw94-mvp5),[GHSA-9w38-p64v-xpmv](https://github.com/advisories/GHSA-9w38-p64v-xpmv),[GHSA-7g45-4rm6-3mm3](https://github.com/advisories/GHSA-7g45-4rm6-3mm3),[GHSA-7g45-4rm6-3mm3](https://github.com/advisories/GHSA-7g45-4rm6-3mm3),[GHSA-gvpg-vgmx-xg6w](https://github.com/advisories/GHSA-gvpg-vgmx-xg6w),[GHSA-h4h5-3hr4-j3g2](https://github.com/advisories/GHSA-h4h5-3hr4-j3g2),[GHSA-h4h5-3hr4-j3g2](https://github.com/advisories/GHSA-h4h5-3hr4-j3g2) | [GHSA-5mg8-w23w-74h3](https://github.com/advisories/GHSA-5mg8-w23w-74h3),[GHSA-5mg8-w23w-74h3](https://github.com/advisories/GHSA-5mg8-w23w-74h3) |  |  |

