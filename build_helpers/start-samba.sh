#!/bin/bash -ex

: '
This script starts a Samba server in a container to use for testing client code
against an SMB server. The following env vars can be defined when calling this
script to modify some of the basic behaviour:

    SMB_PORT: The based port to use for comm         - default: 445
    SMB_USER: The username to use for authentication - default: smbuser
    SMB_PASS: The password to use for authentication - default: smbpass
    SMB_SHARE: The name of the root share to create  - default: share
'

DOCKER_ID="$( docker run \
    --rm \
    --detach \
    --hostname samba.box \
    --publish "${SMB_PORT:-445}":445 \
    --volume "$( pwd )":/tmp/build:z \
    --workdir /tmp/build \
    --env SMB_USER="${SMB_USER:-smbuser}" \
    --env SMB_PASS="${SMB_PASS:-smbpass}" \
    --env SMB_SHARE="${SMB_SHARE:-share}" \
    fedora:latest tail -f /dev/null )"

echo "Detached Samba container started at $DOCKER_ID"

docker exec \
    --interactive \
    "${DOCKER_ID}" \
    /bin/bash -ex -c 'source /dev/stdin' << 'EOF'

echo "Installing Samba"
dnf install -y \
    samba

echo "Creating Samba user"
groupadd smbgroup
useradd $SMB_USER -G smbgroup
(echo $SMB_PASS; echo $SMB_PASS) | smbpasswd -s -a $SMB_USER

echo "Creating smb share and configure permissions"
mkdir -p /srv/samba/dfsroot
chmod -R 0755 /srv/samba/dfsroot
chown -R $SMB_USER:smbgroup /srv/samba/dfsroot
ln -s msdfs:localhost\\$SMB_SHARE /srv/samba/dfsroot/$SMB_SHARE
ln -s msdfs:localhost\\missing,localhost\\$SMB_SHARE-encrypted /srv/samba/dfsroot/$SMB_SHARE-encrypted
ln -s msdfs:localhost\\missing /srv/samba/dfsroot/broken

mkdir -p /srv/samba/$SMB_SHARE
chmod -R 0755 /srv/samba/$SMB_SHARE
chown -R $SMB_USER:smbgroup /srv/samba/$SMB_SHARE

mkdir -p /srv/samba/${SMB_SHARE}-encrypted
chmod -R 0755 /srv/samba/${SMB_SHARE}-encrypted
chown -R $SMB_USER:smbgroup /srv/samba/${SMB_SHARE}-encrypted

echo "Setting basic SMB configuration"
cat > /etc/samba/smb.conf << EOL
[global]
host msdfs = yes
workgroup = WORKGROUP
valid users = @smbgroup
server signing = mandatory
ea support = yes
store dos attributes = yes
vfs objects = xattr_tdb streams_xattr
smb ports = 445

[dfs]
comment = Test Samba DFS Root
path = /srv/samba/dfsroot
browsable = yes
guest ok = no
read only = no
create mask = 0755
msdfs root = yes

[$SMB_SHARE]
comment = Test Samba Share
path = /srv/samba/$SMB_SHARE
browsable = yes
guest ok = no
read only = no
create mask = 0755

[${SMB_SHARE}-encrypted]
comment = Test Encrypted Samba Share
path = /srv/samba/${SMB_SHARE}-encrypted
browsable = yes
guest ok = no
read only = no
create mask = 0755
smb encrypt = required
EOL

echo "Starting SMB Service"
/usr/sbin/smbd
EOF
