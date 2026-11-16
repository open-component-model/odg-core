FROM mcr.microsoft.com/devcontainers/python:3-3.14-trixie@sha256:3b3c45535947751e9dfcd513ef5bee858d221844f55e278e92d1cd8f5b1f2972

RUN apt-get update \
    && apt-get install -y --no-install-recommends kubectl nodejs npm oras \
    && curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin \
#    && npm install -g @anthropic-ai/claude-code \
    && echo 'alias k=kubectl' >> /etc/bash.bashrc \
    && echo 'alias kgp="kubectl get pods"' >> /etc/bash.bashrc \
    && echo 'alias kgs="kubectl get svc"' >> /etc/bash.bashrc \
    && echo 'alias kd="kubectl describe"' >> /etc/bash.bashrc \
    && echo 'alias kl="kubectl logs"' >> /etc/bash.bashrc \
    && echo 'alias kex="kubectl exec -it"' >> /etc/bash.bashrc \
    && echo 'alias py=python3' >> /etc/bash.bashrc

RUN mkdir -p /home/vscode/.kube && chown vscode /home/vscode/.kube

RUN pip3 install uv==0.12.3

COPY --from=aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb /usr/local/bin/trivy /usr/local/bin/trivy
