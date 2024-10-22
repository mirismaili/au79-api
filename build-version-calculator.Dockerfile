FROM bitnami/git:2.46.2
WORKDIR /app
COPY . .
ENTRYPOINT []
CMD echo -n $(( \
    `git rev-list --count HEAD` - \
    `git rev-list --count v$(grep -Po '"version":\s*"\K[^"]*(?=")' package.json) || echo 0` \
  ))
