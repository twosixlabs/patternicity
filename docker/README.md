# Getting hbase and phoenix working on your local machine
## Building the image
cd into this directory and run:

```
docker build -t hbase-phoenix .;
```

## Running the image:

Run:

```
docker run -it -p 2181:2181 -p 16000:16000 -p 16010:16010 -p 16020:16020 -p 16030:16030 -p 8765:8765 hbase-phoenix
```

## Testing that you can actually connect via phoenix

Download the phoenix bundle from https://phoenix.apache.org/download.html extract it somewhere and run

```
cd phoenix-blah-blah-bin/bin;
./sqlline-thin.py localhost:8765
```

## Notes

* The hadoop version is 2.7.7 NOT 3.1.1 upgrading to 3.1.1 didn't work on the first pass so if it's really needed we can revist
* There's no data persistence for now - can fix this by attaching a volume