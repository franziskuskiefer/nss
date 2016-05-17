cd /c/projects/nss; USE_64=1 NSS_ENABLE_TLS_1_3=1 make nss_build_all
if [ $? -eq 0 ]; then
  cd /c/projects/nss/tests/; USE_64=1 HOST=localhost DOMSUF=localdomain NSS_ENABLE_TLS_1_3=1 NSS_TESTS="ssl_gtests gtests" NSS_CYCLES=standard ./all.sh
fi
exit $?
