## What this is about

### Dangling domains in Amazon Web Services

This work is inspired by a problem discussed in [this article](http://www.bishopfox.com/blog/2015/10/fishing-the-aws-ip-pool-for-dangling-domains/), where some brave people went fishing in the AWS IP pool.

**The short story:** For it's simplicity and many more reasons, a lot of websites and services are being hosted on AWS EC2 instances. To be reachable from the internet, active instances [are assigned a public IP by AWS](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html). This IP is elected from the [pool of public AWS IP addresses](https://ip-ranges.amazonaws.com/ip-ranges.json). However, if an instance is stopped or terminated, the assigned IP is automatically released back into the pool. If a fixed IP address is required, one can allocate an [Elastic IP address](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html). Such address is permanently linked to the allocators account and can then be assigned to specific instances. This is highly desirable when a DNS entry pointing at the instance's address must be maintained. But what happens if one releases the Elastic IP address and at the same time forgets to clear the DNS entry? The released address could then be assigned to another AWS user. Since the DNS entry is still pointing at the given IP, the other user now effectively controls the content of our domain. The potential attacker implicitly inherits all trust put into our domain and can impersonate our site, which poses a security risk and possibly leaks sensitive data.

You think this never happens? As the article implies, it does. Repeated reallocation of Elastic IPs allows for crawling the AWS IP space for dangling domains, yielding a broad variety of results.

## What this tool provides

This tool was created to assist in identifying forgotten, potentially dangerous DNS entries as those described above. Your AWS account will be queried during the process. The queries are performed using the [Boto3](https://github.com/boto/boto3) API.

#### Identify candidates for dangling domains

To achieve that, the tool identifies, downloads and evaluates CloudTrail log files from a given AWS account. The evaluation keeps track of *releaseAddress()* and *allocateAddress()* API-calls and outputs a list of ultimately released addresses. For each IP in the list, the tool performs a reverse DNS lookup and outputs the respective domains. Auditors can then (manually) review the list and identify relevant candidates for dangling domains.

**!! Beware:** The logic iterates all CloudTrails and attempts to download all log files it can find. This may induce significant access volumes and therefore **AWS charges**. However, the tool will inform you how many log files it has identified and prompts you to confirm the download. If large log file quantities are an issue for you, consider setting the `-fileLimit` option. 

#### Check against a list of given domains

Setting the `-checkDomains` flag, the tool will instead read a list of domains provided by a text file. The domains are then DNS-lookuped and all corresponding addresses that are not in the AWS IP range are discarded. The remaining IPs are checked against the currenttly allocated Elastic IPs. If any addresses is not covered by an Elastic IP allocation, the tool outputs them. 

## Getting started

For the tool to query your account, you must first [configure AWS access](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html) by `aws configure`.

Make sure that your user policy grants sufficient access rights to perform all queries. Using the SecurityAudit policy is recommended.

To use the basic functionality of identifying candidates for dangling domains, use `python danglingaws.py`. 

To view all options, type `python danglingaws.py -h`.

## Drawbacks of this solution

As the tool needs to download all log files to perform a comprehensive evaluation, it remains yet unclear how well the solution will scale in large production environments. Despite the fact that everything runs clean in my small test environment, I can give no guarantee that every functionality works in a bullet-proof manner in other setups.



