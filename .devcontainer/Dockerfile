FROM mcr.microsoft.com/vscode/devcontainers/python:3.11

RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

RUN pip install requests pandas matplotlib seaborn tqdm jupyter