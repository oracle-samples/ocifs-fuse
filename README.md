# OCIFS - a filesystem to mount OCI Object Storage buckets

The ocifs command provides the ability to mount an
[Oracle Cloud Infrastructure (OCI)](https://www.oracle.com/cloud/)
Object Storage bucket as a filesystem. This makes
OCI Object Storage objects accessible as regular files or directories.
OCIFS is implemented as a FUSE filesystem.

## Installation

### From RPM

OCIFS is available as a RPM package on https://yum.oracle.com/.

### From Source

To build the ocifs command from the source, use the following sequence:

```
$ autoreconf --install
$ ./configure
$ make
```

The ocifs command is then available as src/ocifs/ocifs, and it can be
installed with the following command:

```
# make install
```

## Documentation

The capability and usage of OCIFS are fully documented in the ocifs
man page.

If ocifs is already installed then you can access the man page with:
```
$ man ocifs
```
otherwise, you can view it from the source repository with:
```
$ man doc/ocifs.1
```

The following is a quick and simple overview on how to mount/unmount
an OCI Object Storage bucket with ocifs.

### Authentication

To mount an OCI Object Storage bucket with ocifs, you must authenticate
with OCI. A simple way to authenticate is to use the API key-based
authentication. To do so, you need to create an OCI SDK and CLI
configuration file (~/.oci/config) as defined in the OCI documentation:

  https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm

The configuration file must have the following entries: user, fingerprint,
tenancy, region, key_file. OCIFS uses the entries defined in the DEFAULT
profile.

For other authentication methods, refer the ocifs man page.

### Mounting an OCI Object Storage Bucket

To mount an OCI Object Storage bucket, do either:

```
$ ocifs <oci-object-storage-bucket-name> <dir>
```

or:

```
# mount -t fuse.ocifs <oci-object-storage-bucket-name> <dir>
```
Once an OCI Object Storage bucket is mounted, objects from that bucket are
accessible as regular files, and ocifs simulates a directory structure from
prefix strings present in object names that includes one or more forward
slashes (/).

### Unmounting an OCI Object Storage Bucket

To mount an OCI Object Storage bucket, do either:

```
$ fusermount -u <dir>
```

or:

```
# umount <dir>
```

## Examples

The following examples use the API Key-Based authentication:

### Configuration

Configuration file example:

```
$ cat ~/.oci/config
[DEFAULT]
user=ocid1.user.oc1..<unique_ID>
fingerprint=12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef
tenancy=ocid1.tenancy.oc1..<unique_ID>
region=us-ashburn-1
key_file=~/.oci/oci_api_key_public.pem
```

### Mounting an OCI Object Storage bucket

With the ocifs command:

```
$ ocifs my-bucket ~/mnt
```

With the mount command:

```
# mount -t fuse.ocifs my-bucket /mnt
```

### Unmount an OCI Object Storage bucket path

With the ocifs command:

```
$ fusermount -u ~/mnt
```

With the mount command:

```
# umount /mnt
```

## Contributing

This project welcomes contributions from the community. Before submitting a pull request, please [review our contribution guide](./CONTRIBUTING.md)

## Security

Please consult the [security guide](./SECURITY.md) for our responsible security vulnerability disclosure process

## License

Copyright (c) 2023 Oracle and/or its affiliates.

Released under the Universal Permissive License v1.0 as shown at
<https://oss.oracle.com/licenses/upl/>.
