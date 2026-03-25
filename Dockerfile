FROM debian:13
USER root

# `-` is reserved by deb maintainer, should use '~' instead
# If no version is specified, the latest available version will be installed
ARG version

RUN useradd --create-home --shell /bin/false ds_proxy

# Add DS/DN repo
RUN apt-get update && apt-get -y install curl gpg \
    && curl -sS https://demarche.numerique.gouv.fr/packages.demarche.numerique.gouv.fr.gpg | gpg --dearmor -o /usr/share/keyrings/packages.demarche.numerique.gouv.fr.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/packages.demarche.numerique.gouv.fr.gpg] http://packages.demarche.numerique.gouv.fr/jammy/ /" > /etc/apt/sources.list.d/packages_demarche_numerique_gouv_fr_jammy.list \
    && apt-get update \
    && apt-get -y install --no-install-recommends ca-certificates \
    && apt-get -y install ds-proxy${version:+=${version}} \
    && apt-get remove --purge -y curl gpg \
    && apt-get autoremove -y \
    && apt-get clean

USER ds_proxy

EXPOSE 4444

ENTRYPOINT ["/usr/bin/ds_proxy"]
