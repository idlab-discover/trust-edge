
This repository contains the code related to the [paper](https://doi.org/10.48550/arXiv.2405.10131) "Trusting the Cloud-Native Edge: Remotely Attested Kubernetes Workers" accepted to COHERENT 2024. It provides a PoC implementation of an architecture used to enroll edge devices into a Kubernetes cluster after succesfull attestation.

### Folders:

`attesation-operator`: The controller that manages the attestation of an edge device.

`deploy-edgenode`: Helm Chart to deploy an EdgeNode CR to K8s.

`deploy-keylime-cloud`: An early fork of the keylime operator modified to deploy our custom images to K8s. Forked from [this commit](https://github.com/keylime/attestation-operator/tree/af881f0d4216851316e46dac07f4cac8add443c2).

`keylime`: Our fork of the keylime repository with our modifications and contributions. Forked from [this commit](https://github.com/keylime/keylime/tree/fb9646448524d7ee9f46226fe0610b451dc5bda4). 


### Prerequisites:

A full installation of [Feather](https://github.com/idlab-discover/feather) as a systemd service is required. This software does not install it but only provides it with credentials.

The [Keylime Rust agent](https://github.com/keylime/rust-keylime) must be present on the edge device running as a systemd service. Use the agent's config in `/etc/keylime/agent.conf` on the edge device to point it to the cluster and the exposed ports for the cloud components. 

This prototype exposes the cloud components as NodePorts using the following ports:
```
registrar   30001
verifier    30002
```

You might want to change this depending on the network configurations of your cluster.

A basic kubeconfig must be present on the edge device (`/home/user/.kube/kubeconfig`) containing cluster information such as CA and IP info. Context and User will be automatically generated.

### Creating cloud images:

As our images are modified Keylime images, their tools can be used to build the images. `keylime/docker/release/`contains scripts to generate the Dockerfiles and build the images. Make sure to edit the `build_locally.sh` to point to your image repository.


### Deploying cloud images:

`deploy-keylime-cloud`contains an early fork of the [Keylime operator](https://github.com/keylime/attestation-operator) which at that point only consisted of a Helm Charts to deploy the images. Some alterations were made to make this work with our custom images. 

Make sure to point the `build/values.yaml`file to the images in your own repository and manually deploy any secrets required to access your them (if they are private).

The images can be deployed using the following commands:

```
make helm-build
make helm-deploy
```

Running `make help` in the root of `deploy-keylime-cloud` will give an overview of all available make commands. 

### Deploying the controller:

The controller was created using [Kubebuilder](https://book.kubebuilder.io) as a scaffold and thus follows its deployment steps. Make commands are provided for this. 

To install the CRDs for the EdgeNode:
```
# Generate yamls
make build-installer

# Install yamls
make install
```

To build and deploy the controller image:

```
# Create a docker image
make docker-build IMG=<img-name>

# Push the docker image to a configured container registry
make docker-push IMG=<img-name>

# Deploy the controller manager manifests to the cluster.
make deploy
```

### Deploying EdgeNode resource:

Once all other components are installed a sysadmin can deploy an EdgeNode CR to respresent the edge device in the cluster. 

Provide the TPM's ekcert in `templates/edgenode.yaml` and a [Keylime compatible boot log](https://keylime.readthedocs.io/en/latest/user_guide/use_measured_boot.html) in `config.json`.

Deploy using Helm:
```
helm install <some_name> . -n <some_namespace>
```

The controller will detect the presence of a new device and as soon as that device contacts the cluster it will be attestated and either welcomed into the cluster or denied access based on its attestation status.