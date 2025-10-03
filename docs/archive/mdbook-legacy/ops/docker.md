# Dockerfile

Setagaya controller runs inside a Docker container. In order to successfully build a Docker image for your own controller, you will need these files:

1. kubeconfig
2. GCP config JSON (only if you are using GCP)
3. Config file for setagaya controller itself.

## kubeconfig and setagaya controller config

```
COPY config/kube_configs /root/.kube
COPY config_${env}.json /config.json
```

For kubeconfig, as you can see in the Dockerfile , you only need to provide the kubeconfigs here: `setagaya/setagaya/config/kube_configs`.

For the setagaya config file, you will need to put it here `setagaya/setagaya`, which is the building context of this Dockerfile. `${env}` here is the building argument. If your k8s cluster is `gcp_tokyo`, you can name your config file as `config_gcp_tokyo` and build the Docker image as follows:

`docker build -t ${image_name} --build-arg env=gcp_tokyo .`

## GCP config

```
ADD ./setagaya-gcp.json /auth/setagaya-gcp.json
```

You will need to add the gcp auth file to the build context, which you can learn here: [https://cloud.google.com/docs/authentication/getting-started](https://cloud.google.com/docs/authentication/getting-started)
