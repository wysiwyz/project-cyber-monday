# Project Cyber Monday

Now that the CKAD and CKA are taken down, this repository is created to keep track of learning process of the remainder three certificates - **CKS**, **KCNA** and **KCSA**. Call me dumb spender but I really fancy that blue jacket.

## Plan

1. Watch CKS Killer simulator videos and take notes - 24 of these bad guys

2. Finish KK_Course by 15 Dec

3. Acquired KCNA and KCSA by 12 Dec ✅

4. Rework KK_CKS labs before 22 Dec

5. Take on the first Killer_sh_CKS before 22 Dec

## Important URL

[Securing a cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/)

[Network policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

[CIS benchmark Kubernetes](https://www.cisecurity.org/benchmark/kubernetes)

[Specify TLS secret in an Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls)

[Restrict cloud metadata API access](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#restricting-cloud-metadata-api-access)

[Deploy Kubernetes dashboard UI](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/#accessing-the-dashboard-ui)

[Control access to the Kubernetes API](https://kubernetes.io/docs/concepts/security/controlling-access/)

[API access control - Anonymous requests](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests)

[Use RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

[User the default service account to access the API server](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server)

[kubeadm upgrade](https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-upgrade/)

[Authenticating users in K8s](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)

[Restrict Container Access to Resources with AppArmor](https://kubernetes.io/docs/tutorials/security/apparmor/)

[Restrice Container Syscalls with Seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)

[OPA Gatekeeper: Policy and Governance for K8s](https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/)

[Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

[Kubernetes Secret](https://kubernetes.io/docs/concepts/configuration/secret/)

[Runtime Class](https://kubernetes.io/docs/concepts/containers/runtime-class/)

[Manage TLS Certificates in a Cluster](https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/)

[Why do I need admission controllers](https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/#why-do-i-need-admission-controllers)

[ImagePolicyWebhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook)

[11 Ways (not) to Get Hacked](https://kubernetes.io/blog/2018/07/18/11-ways-not-to-get-hacked/#10-scan-images-and-run-ids)

[The Falco Project](https://falco.org/docs/)


## Execution record

Refer to this [excel workbook](./cks_kcsa_kcna.xlsx).


## Simulator walkthrough

| #  | List                |
|----|---------------------|
|  1 | [Question 01](#q1)  |
|  2 | [Question 02](#q2)  |
|  3 | [Question 03](#q3)  | 
|  4 | [Question 04](#q4)  | 
|  5 | [Question 05](#q5)  | 
|  6 | [Question 06](#q6)  | 
|  7 | [Question 07](#q7)  | 
|  8 | [Question 08](#q8)  | 
|  9 | [Question 09](#q9)  | 
| 10 | [Question 10](#q10) | 
| 11 | [Question 11](#q11) | 
| 12 | [Question 12](#q12) | 
| 13 | [Question 13](#q13) | 
| 14 | [Question 14](#q14) | 
| 15 | [Question 15](#q15) | 
| 16 | [Question 16](#q16) | 
| 17 | [Question 17](#q17) | 
| 18 | [Question 18](#q18) | 
| 19 | [Question 19](#q19) | 
| 20 | [Question 20](#q20) | 
| 21 | [Question 21](#q21) | 
| 22 | [Question 22](#q22) | 


### Q1

You have access to multiple clusters from your main terminal through kubectl contexts. Write all context names into /opt/course/1/contexts, one per line.

From the kubeconfig extract the certificate of user restricted@infra-prod and write it decoded to /opt/course/1/cert.

Keywords: `client-certificate-data`, `base64 decode`

[Solution #1](./sol_01.txt)


### Q2

Falco is installed with default configuration on node cluster1-node1. Connect using ssh cluster1-node1. Use it to:

Find a Pod running image nginx which creates unwanted package management processes inside its container. 

1. Find a Pod running image httpd which modifies /etc/passwd.

2. Save the Falco logs for case 1 under /opt/course/2/falco.log in format:

time-with-nanosconds,container-id,container-name,user-name

No other information should be in any line. Collect the logs for at least 30 seconds.

Afterwards remove the threads (both 1 and 2) by scaling the replicas of the Deployments that control the offending Pods down to 0.


Keywords: `Falco`, `fields for conditions and outputs`, `falco_rules`

[Solution #2](./sol_02.txt)


### Q3

You received a list from the DevSecOps team which performed a security investigation of the k8s cluster1 (workload-prod). The list states the following about the apiserver setup:

- Accessible through a NodePort Service

Change the apiserver setup so that:

- Only accessible through a ClusterIP Service

Keywords: `kubernetes-service-node-port`, `service/kubernetes`

[Solution #3](./sol_03.txt)


### Q4

There is Deployment container-host-hacker in Namespace team-red which mounts /run/containerd as a hostPath volume on the Node where it's running. This means that the Pod can access various data about other containers running on the same Node.

To prevent this configure Namespace team-red to enforce the baseline Pod Security Standard. Once completed, delete the Pod of the Deployment mentioned above.

Check the ReplicaSet events and write the event/log lines containing the reason why the Pod isn't recreated into /opt/course/4/logs.

Keywords: `PodSecurityStandard`

[Solution #4](./sol_04.txt)


### Q5

You're ask to evaluate specific settings of cluster2 against the CIS Benchmark recommendations. Use the tool kube-bench which is already installed on the nodes.

Connect using ssh cluster2-controlplane1 and ssh cluster2-node1.

On the master node ensure (correct if necessary) that the CIS recommendations are set for:

1. The --profiling argument of the kube-controller-manager

2. The ownership of directory /var/lib/etcd

On the worker node ensure (correct if necessary) that the CIS recommendations are set for:

3. The permissions of the kubelet configuration /var/lib/kubelet/config.yaml

4. The --client-ca-file argument of the kubelet

Keywords: `CIS benchmark`, `kube-bench`, `--profiling`

[Solution #5](./sol_05.txt)


### Q6

(can be solved in any kubectl context)

There are four Kubernetes server binaries located at /opt/course/6/binaries. You're provided with the following verified sha512 values for these:

kube-apiserver f417c0555bc0167355589dd1afe23be9bf909bf98312b1025f12015d1b58a1c62c9908c0067a7764fa35efdac7016a9efa8711a44425dd6692906a7c283f032c

kube-controller-manager 60100cc725e91fe1a949e1b2d0474237844b5862556e25c2c655a33boa8225855ec5ee22fa4927e6c46a60d43a7c4403a27268f96fbb726307d1608b44f38a60

kube-proxy 52f9d8ad045f8eee1d689619ef8ceef2d86d50c75a6a332653240d7ba5b2a114aca056d9e513984ade24358c9662714973c1960c62a5cb37dd375631c8a614c6

kubelet 4be40f2440619e990897cf956c32800dc96c2c983bf64519854a3309fa5aa21827991559f9c44595098e27e6f2ee4d64a3fdec6baba8a177881f20e3ec61e26c

Delete those binaries that don't match with the sha512 values above.

Keywords: `sha512sum`

[Solution #6](./sol_06.txt)


### Q7

The Open Policy Agent and Gatekeeper have been installed to, among other things, enforce blacklisting of certain image registries. Alter the existing constraint and/or template to also blacklist images from very-bad-registry.com.

Test it by creating a single Pod using image very-bad-registry.com/image in Namespace default, it shouldn't work.

You can also verify your changes by looking at the existing Deployment untrusted in Namespace default, it uses an image from the new untrusted source. The OPA contraint should throw violation messages for this one.

Keywords: `constraint`, `constrainttemplate`, `rego`

[Solution #6](./sol_07.txt)


### Q8

The Kubernetes Dashboard is installed in Namespace kubernetes-dashboard and is configured to:

1. Allow users to "skip login"

2. Allow insecure access (HTTP without authentication)

3. Allow basic authentication

4. Allow access from outside the cluster

You are asked to make it more secure by:

1. Deny users to "skip login"

2. Deny insecure access, enforce HTTPS (self signed certificates are ok for now)

3. Add the --auto-generate-certificates argument

4. Enforce authentication using a token (with possibility to use RBAC)

5. Allow only cluster internal access

Keywords: `

[Solution #8](./sol_08.txt)


### Q9

Some containers need to run more secure and restricted. There is an existing AppArmor profile located at /opt/course/9/profile for this.

Install the AppArmor profile on Node cluster1-node1. Connect using ssh cluster1-node1.

Add label security=apparmor to the Node

Create a Deployment named apparmor in Namespace default with:

- One replica of image nginx:1.19.2
- NodeSelector for security=apparmor
- Single container named c1 with the AppArmor profile enabled

The Pod might not run properly with the profile enabled. Write the logs of the Pod into /opt/course/9/logs so another team can work on getting the application running.

Keywords:

[Solution #9](./sol_09.txt)


### Q10

Team purple wants to run some of their workloads more secure. Worker node cluster1-node2 has container engine containerd already installed and it's configured to support the runsc/gvisor runtime.

Create a RuntimeClass named gvisor with handler runsc.

Create a Pod that uses the RuntimeClass. The Pod should be in Namespace team-purple, named gvisor-test and of image nginx:1.19.2. Make sure the Pod runs on cluster1-node2.

Write the dmesg output of the successfully started Pod into /opt/course/10/gvisor-test-dmesg.

Keywords:

[Solution #10](./sol_10.txt)


### Q11

There is an existing Secret called database-access in Namespace team-green.

Read the complete Secret content directly from ETCD (using etcdctl) and store it into /opt/course/11/etcd-secret-content. Write the plain and decoded Secret's value of key "pass" into /opt/course/11/database-password.

Keywords:

[Solution #11](./sol_11.txt)


### Q12

You're asked to investigate a possible permission escape in Namespace restricted. The context authenticates as user restricted which has only limited permissions and shouldn't be able to read Secret values.

Try to find the password-key values of the Secrets secret1, secret2 and secret3 in Namespace restricted. Write the decoded plaintext values into files /opt/course/12/secret1, /opt/course/12/secret2 and /opt/course/12/secret3.

Keywords:

[Solution #12](./sol_12.txt)


### Q13

There is a metadata service available at http://192.168.100.21:32000 on which Nodes can reach sensitive data, like cloud credentials for initialisation. By default, all Pods in the cluster also have access to this endpoint. The DevSecOps team has asked you to restrict access to this metadata server.

In Namespace metadata-access:

- Create a NetworkPolicy named metadata-deny which prevents egress to 192.168.100.21 for all Pods but still allows access to everything else

- Create a NetworkPolicy named metadata-allow which allows Pods having label role: metadata-accessor to access endpoint 192.168.100.21

There are existing Pods in the target Namespace with which you can test your policies, but don't change their labels.

Keywords:

[Solution #13](./sol_13.txt)


### Q14

There are Pods in Namespace team-yellow. A security investigation noticed that some processes running in these Pods are using the Syscall kill, which is forbidden by a Team Yellow internal policy.

Find the offending Pod(s) and remove these by reducing the replicas of the parent Deployment to 0.

Keywords:

[Solution #14](./sol_14.txt)


### Q15

In Namespace team-pink there is an existing Nginx Ingress resources named secure which accepts two paths /app and /api which point to different ClusterIP Services.

From your main terminal you can connect to it using for example:

- HTTP: curl -v http://secure-ingress.test:31080/app
- HTTPS: curl -kv https://secure-ingress.test:31443/app

Right now it uses a default generated TLS certificate by the Nginx Ingress Controller.

You're asked to instead use the key and certificate provided at /opt/course/15/tls.key and /opt/course/15/tls.crt. As it's a self-signed certificate you need to use curl -k when connecting to it.

Keywords:

[Solution #15](./sol_15.txt)


### Q16

There is a Deployment image-verify in Namespace team-blue which runs image registry.killer.sh:5000/image-verify:v1. DevSecOps has asked you to improve this image by:

1. Changing the base image to alpine:3.12
2. Not installing curl
3. Updating nginx to use the version constraint &gt;=1.18.0
4. Running the main process as user myuser

Do not add any new lines to the Dockerfile, just edit existing ones. The file is located at /opt/course/16/image/Dockerfile.

Tag your version as v2

Keywords:

[Solution #16](./sol_16.txt)


### Q17

Audit Logging has been enabled in the cluster with an Audit Policy located at /etc/kubernetes/audit/policy.yaml on cluster2-controlplane1.

Change the configuration so that only one backup of the logs is stored.

Alter the Policy in a way that it only stores logs:

1. From Secret resources, level Metadata
2. From "system:nodes" userGroups, level RequestResponse

After you altered the Policy make sure to empty the log file so it only contains entries according to your changes, like using truncate -s 0 /etc/kubernetes/audit/logs/audit.log .

Keywords:

[Solution #17](./sol_17.txt)


### Q18

Namespace security contains five Secrets of type Opaque which can be considered highly confidential. The latest Incident-Prevention-Investigation revealed that ServiceAccount p.auster had too broad access to the cluster for some time. This SA should've never had access to any Secrets in that Namespace.

Find out which Secrets in Namespace security this SA did access by looking at the Audit Logs under /opt/course/18/audit.log.

Change the password to any new string of only those Secrets that were accessed by this SA.

Keywords:

[Solution #18](./sol_18.txt)


### Q19

The Deployment immutable-deployment in Namespace team-purple should run immutable, it's created from file /opt/course/19/immutable-deployment.yaml. Even after a successful break-in, it shouldn't be possible for an attacker to modify the filesystem of the running container.

Modify the Deployment in a way that no processes inside the container can modify the local filesystem, only /tmp directory should be writeable. Don't modify the Docker image.

Save the updated YAML under /opt/course/19/immutable-deployment-new.yaml and update the running Deployment.

Keywords:

[Solution #19](./sol_19.txt)


### Q20

The cluster is running Kubernetes 1.27.6, update it to 1.28.2.

Use apt package manager and kubeadm for this.

Use ssh cluster3-controlplane1 and ssh cluster3-node1 to connect to the instances.

Keywords: `Upgrading kubeadm clusters`

[Solution #20](./sol_20.txt)


### Q21

The Vulnerability Scanner trivy is installed on your main terminal. Use it to scan the following images for known CVEs:

- nginx:1.16.1-alpine
- k8s.gcr.io/kube-apiserver:v1.18.0
- k8s.gcr.io/kube-controller-manager:v1.18.0
- docker.io/weaveworks/weave-kube:2.7.0

Write all images that don't contain the vulnerabilities CVE-2020-10878 or CVE-2020-1967 into /opt/course/21/good-images.

Keywords: `trivy`

[Solution #21](./sol_21.txt)


### Q22

The Release Engineering Team has shared some YAML manifests and Dockerfiles with you to review. The files are located under /opt/course/22/files.

As a container security expert, you are asked to perform a manual static analysis and find out possible security issues with respect to unwanted credential exposure. Running processes as root is of no concern in this task.

Write the filenames which have issues into /opt/course/22/security-issues.

Keywords: `manual static analysis`, `credential exposure`

[Solution #22](./sol_22.txt)