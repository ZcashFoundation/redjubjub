
# Frosty messages

## Headers

All messages in Frost have the following header:

| Bytes | Field Name   | Data Type |
|----- |------------ |--------- |
| 1     | Message Type | `u8`      |
| 1     | Version      | `u8`      |
| 1     | Source       | `u8`      |
| 1     | Destination  | `u8`      |

The `Message Type` and `Version` fields specify the data that follows after the header. The sender is uniquely identified by the `Source` field and the receiver is uniquely identified by the `Destination` field.

## Data

The following message types specify the structure of the data contained in a Frosty message. The `Version` of each message equals 1.

### Message Type 1

Request signing commitments from other participants.

**Data**:

| Bytes | Description                     | Data Type |
|----- |------------------------------- |--------- |
| 2     | Number of requested commitments | `u16`     |

### Message Type 2

Send the requested signing commitments.

**Data**:

| Bytes      | Description                       | Data Type     |
|---------- |--------------------------------- |------------- |
| 2          | Number of signing commitments `n` | `u16`         |
| 512 \* `n` | Signing commitments               | `[u8; 512*n]` |

### Message Type = 3

Send the message (document) to be signed.

**Data**:

| Bytes      | Description               | Data Type     |
|---------- |------------------------- |------------- |
| 2          | Message length `l`        | `u16`         |
| `l`        | Message to be signed      | `[u8; l]`     |
| 1          | Number of commitments `t` | `u8`          |
| 512 \* `t` | Signing commitments       | `[u8; 512*t]` |
