#! /bin/sh

trap 'rm -f test.json' EXIT


# missing required cmdline args
gnunet-auction-create      -r 1 -d foo -p test.json && exit 1
gnunet-auction-create -s 1      -d foo -p test.json && exit 1
gnunet-auction-create -s 1 -r 1        -p test.json && exit 1
gnunet-auction-create -s 1 -r 1 -d foo              && exit 1


# no pricemap
rm -f test.json
gnunet-auction-create -s 1 -r 1 -d foo -p test.json && exit 1


# json errors
cat <<DOG >test.json
[,]
DOG
gnunet-auction-create -s 1 -r 1 -d foo -p test.json && exit 1

cat <<DOG >test.json
bla
DOG
gnunet-auction-create -s 1 -r 1 -d foo -p test.json && exit 1


# unexpected structures
cat <<DOG >test.json
{"foo": "bar"}
DOG
gnunet-auction-create -s 1 -r 1 -d foo -p test.json && exit 1

cat <<DOG >test.json
{"currency": "foo"}
DOG
gnunet-auction-create -s 1 -r 1 -d foo -p test.json && exit 1

cat <<DOG >test.json
{"prices": []}
DOG
gnunet-auction-create -s 1 -r 1 -d foo -p test.json && exit 1

cat <<DOG >test.json
{"currency": "foo", "prices": "bar"}
DOG
gnunet-auction-create -s 1 -r 1 -d foo -p test.json && exit 1


# wrong array content
cat <<DOG >test.json
{"currency": "foo", "prices": []}
DOG
gnunet-auction-create -s 1 -r 1 -d foo -p test.json && exit 1

cat <<DOG >test.json
{"currency": "foo", "prices": ["bar"]}
DOG
gnunet-auction-create -s 1 -r 1 -d foo -p test.json && exit 1

cat <<DOG >test.json
{"currency": "foo", "prices": [null]}
DOG
gnunet-auction-create -s 1 -r 1 -d foo -p test.json && exit 1

cat <<DOG >test.json
{"currency": "foo", "prices": [1, 2]}
DOG
gnunet-auction-create -s 1 -r 1 -d foo -p test.json && exit 1


# correct example
cat <<DOG >test.json
{"currency": "foo", "prices": [2, 1]}
DOG
gnunet-auction-create -s 1 -r 1 -d foo -p test.json || exit 1

rm -f test.json
