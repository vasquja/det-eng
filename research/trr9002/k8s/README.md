# Command Execution in a Running Container (Kubernetes)

> Prose uses Simplified Technical English (ASD-STE100) where practical.
> API paths, resource names, field names, and ATT&CK IDs are technical names.

## Metadata

| Key          | Value |
|--------------|-------|
| ID           | TRR9002 |
| External IDs | T1609 |
| Tactics      | Execution |
| Platforms    | Kubernetes |
| Contributors | det-eng |
| Status       | draft |

### Scope Statement

This TRR covers command execution inside a running container through the
Kubernetes control interfaces: the API server and the kubelet.

This TRR does not cover these related actions:

- A command that goes directly to a container runtime on a node, for example
  `crictl exec` or `docker exec` through a runtime socket. The Kubernetes
  control interfaces do not see these commands. A Linux or Docker TRR must
  cover them.
- A new workload that runs adversary code. ATT&CK T1610 (Deploy Container)
  covers this.
- An escape from a container to its node. ATT&CK T1611 (Escape to Host)
  covers this.

ATT&CK T1609 also includes the Docker daemon. This report covers Kubernetes
only.

## Technique Overview

Kubernetes runs applications in containers. An administrator can run a
command inside a running container, or open an interactive shell in it. The
`kubectl exec` command does this. Administrators use it to examine and repair
live applications.

An adversary can use the same feature. The adversary needs credentials that
have the necessary permission. With those credentials, the adversary can run
commands in each container that the credentials can reach. The command runs
with the identity and the access of that container. The adversary can then
read the application's files, secrets, and network. The adversary does not
need to deploy new software or change the application.

This technique uses a legitimate administration feature. Each request looks
like normal administration work. The differences are in who sends the
request, from which location, and into which container. This report
identifies the paths that lead to command execution in a container. It shows
where the cluster records each path, and which records give a detection
opportunity.

## Technical Background

<!-- Next section. To be written. -->

## Procedures

<!-- To be written. -->

## Detection Strategy

<!-- To be written. -->

## Available Emulation Tests

<!-- To be written. -->

## Detections

<!-- To be written. -->

## References

- MITRE ATT&CK, T1609 Container Administration Command:
  <https://attack.mitre.org/techniques/T1609/>
