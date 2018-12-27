docker run -d -p 3030:3030 \
    -v `pwd`/config/elastalert.yaml:/opt/elastalert/config.yaml \
    -v `pwd`/config/config.json:/opt/elastalert-server/config/config.json \
    -v `pwd`/rules:/opt/elastalert/rules \
    -v `pwd`/rule_templates:/opt/elastalert/rule_templates \
    -v `pwd`/scripts:/opt/scripts \
    --net="host" \
    --name elastalert bitsensor/elastalert:0.0.10
