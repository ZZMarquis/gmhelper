#!/bin/bash

./mvnw clean deploy -Dgpg.passphrase=${GPG_PWD} -DskipTests=true -P 'oss-release'
