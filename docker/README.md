# gnunet-docker
A Dockerfile (and maybe later docker-compose.yml) for getting a running GNUnet docker container.

> This README and parts of the Dockerfile were adapted from https://github.com/compiaffe/gnunet-docker


## Build it
This will take quite a while and will consume a bit of data.

First you need to go to the root of this repo.

```bash
cd ..
```

Now you can build the image.

```bash
docker build -t gnunet .
```

## Start it from the newly created gnunet image
Start a container from `gnunet` image, which can access /dev/net/tun, has access to the host network. We are going to name it `gnunet1`.

Note the `--rm` that will delete the container as soon as you stop it and `-ti` gives you an interactive terminal.

#### Linux Users
```bash
docker run \
  --rm \
  -ti \
  --privileged \
  --name gnunet1 \
  --net=host \
  -v /dev/net/tun:/dev/net/tun \
  gnunet
```

#### Mac Users
```bash
docker run \
  --rm \
  -it \
  --privileged \
  --name gnunet1 \
  -e LOCAL_PORT_RANGE='40001 40200' \
  -e GNUNET_PORT=2086 \
  -p 2086:2086 \
  -p 2086:2086/udp \
  -p40001-40200:40001-40200 \
  -p40001-40200:40001-40200/udp \
  gnunet
```

This terminal will keep on printing to screen at the moment. So go on in a new terminal please.

Don't worry about warnings too much...

## Check if you are connected
Open a new terminal and connect to the container we just started:

```bash
docker exec -it gnunet1 gnunet-peerinfo -i
```

If you get a list of peers, all is good.

## Multiple containers on the same host
### Running
#### Run Container 1
```bash
export GPORT=2086 LPORT='40001-40200' GNAME=gnunet1
docker run \
  --rm \
  -it \
  --privileged \
  -e GNUNET_PORT=$GPORT \
  -e LOCAL_PORT_RANGE="${LPORT/-/ }" \
  -p $GPORT:$GPORT \
  -p $GPORT:$GPORT/udp \
  -p$LPORT:$LPORT \
  -p$LPORT:$LPORT/udp \
  --name $GNAME \
  gnunet
```

#### Run Container 2
```bash
export GPORT=2087 LPORT='40201-40400' GNAME=gnunet2
docker run \
  --rm \
  -it \
  --privileged \
  -e GNUNET_PORT=$GPORT \
  -e LOCAL_PORT_RANGE="${LPORT/-/ }" \
  -p $GPORT:$GPORT \
  -p $GPORT:$GPORT/udp \
  -p$LPORT:$LPORT \
  -p$LPORT:$LPORT/udp \
  --name $GNAME \
  gnunet
```

### Testing cadet example
#### Container 1
```bash
$ docker exec -it gnunet1 bash
$ gnunet-peerinfo -s
I am peer `VWPN1NZA6YMM866EJ5J2NY47XG692MQ6H6WASVECF0M18A9SCMZ0'.
$ gnunet-cadet -o asdasd
```

#### Container 2
```bash
$ docker exec -it gnunet2 bash
$ gnunet-cadet VWPN1NZA6YMM866EJ5J2NY47XG692MQ6H6WASVECF0M18A9SCMZ0 asdasd
```

### Testing file sharing example
#### Container 1
```bash
$ docker exec -it gnunet1 bash
$ echo 'test' > test.txt
$ gnunet-publish test.txt
Publishing `/test.txt' done.
URI is `gnunet://fs/chk/1RZ7A8TAQHMF8DWAGTSZ9CSA365T60C4BC6DDS810VM78D2Q0366CRX8DGFA29EWBT9BW5Y9HYD0Z1EAKNFNJQDJ04QQSGTQ352W28R.7MYB03GYXT17Z93ZRZRVV64AH9KPWFSVDEZGVE84YHD63XZFJ36B86M48KHTZVF87SZ05HBVB44PCXE8CVWAH72VN1SKYPRK1QN2C98.5'.
```

#### Container 2
```bash
$ docker exec -it gnunet2 bash
$ gnunet-download -o out.file "gnunet://fs/chk/1RZ7A8TAQHMF8DWAGTSZ9CSA365T60C4BC6DDS810VM78D2Q0366CRX8DGFA29EWBT9BW5Y9HYD0Z1EAKNFNJQDJ04QQSGTQ352W28R.7MYB03GYXT17Z93ZRZRVV64AH9KPWFSVDEZGVE84YHD63XZFJ36B86M48KHTZVF87SZ05HBVB44PCXE8CVWAH72VN1SKYPRK1QN2C98.5"
100% [============================================================]
Downloading `out.file' done (0 b/s).
$ cat out.file
test
```

