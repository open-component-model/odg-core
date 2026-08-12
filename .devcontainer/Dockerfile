FROM mcr.microsoft.com/devcontainers/python:3-3.14-trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends kubectl nodejs npm \
#    && npm install -g @anthropic-ai/claude-code \
    && echo 'alias k=kubectl' >> /etc/bash.bashrc \
    && echo 'alias kgp="kubectl get pods"' >> /etc/bash.bashrc \
    && echo 'alias kgs="kubectl get svc"' >> /etc/bash.bashrc \
    && echo 'alias kd="kubectl describe"' >> /etc/bash.bashrc \
    && echo 'alias kl="kubectl logs"' >> /etc/bash.bashrc \
    && echo 'alias kex="kubectl exec -it"' >> /etc/bash.bashrc \
    && echo 'alias py=python3' >> /etc/bash.bashrc

RUN mkdir -p /home/vscode/.kube && chown vscode /home/vscode/.kube

COPY requirements*.txt /tmp/
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install \
    -r /tmp/requirements.txt \
    -r /tmp/requirements-dev.txt \
    && rm /tmp/requirements*.txt
