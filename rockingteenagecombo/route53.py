from dataclasses import dataclass

from boto3 import client

from .apigateway import ApiGateway


@dataclass
class Route53(ApiGateway):

    def __post_init__(self):
        self.route53 = client("route53")

    def get_all_zones(self):
        """Same behaviour of list_host_zones, but transparently handling
        pagination."""
        zones = {"HostedZones": []}

        new_zones = route53.list_hosted_zones(MaxItems="100")
        while new_zones["IsTruncated"]:
            zones["HostedZones"] += new_zones["HostedZones"]
            new_zones = route53.list_hosted_zones(
                Marker=new_zones["NextMarker"], MaxItems="100"
            )

        zones["HostedZones"] += new_zones["HostedZones"]
        return zones

    def update_route53_records(self, domain_name, dns_name):
        """
        Updates Route53 Records following GW domain creation
        """
        zone_id = self.get_hosted_zone_id_for_domain(domain_name)

        is_apex = (
                route53.get_hosted_zone(Id=zone_id)["HostedZone"]["Name"][
                :-1]
                == domain_name
        )
        if is_apex:
            record_set = {
                "Name": domain_name,
                "Type": "A",
                "AliasTarget": {
                    "HostedZoneId": "Z2FDTNDATAQYW2",
                    # This is a magic value that means "CloudFront"
                    "DNSName": dns_name,
                    "EvaluateTargetHealth": False,
                },
            }
        else:
            record_set = {
                "Name": domain_name,
                "Type": "CNAME",
                "ResourceRecords": [{"Value": dns_name}],
                "TTL": 60,
            }

        # Related: https://github.com/boto/boto3/issues/157
        # and: http://docs.aws.amazon.com/Route53/latest/APIReference
        # /CreateAliasRRSAPI.html
        # and policy: https://spin.atomicobject.com/2016/04/28/route-53
        # -hosted-zone-managment/
        # pure_zone_id = zone_id.split('/hostedzone/')[1]

        # XXX: ClientError: An error occurred (InvalidChangeBatch) when
        # calling the ChangeResourceRecordSets operation:
        # Tried to create an alias that targets
        # d1awfeji80d0k2.cloudfront.net., type A in zone Z1XWOQP59BYF6Z,
        # but the alias target name does not lie within the target zone
        response = route53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {"Action": "UPSERT", "ResourceRecordSet": record_set}]
            },
        )

        return response

    def get_domain_name(self, domain_name, route53=True):
        """
        Scan our hosted zones for the record of a given name.

        Returns the record entry, else None.

        """
        # Make sure api gateway domain is present
        try:
            self.apigateway.get_domain_name(domainName=domain_name)
        except Exception:
            return None

        if not route53:
            return True

        try:
            zones = self.get_all_zones()
            for zone in zones["HostedZones"]:
                records = self.route53.list_resource_record_sets(
                    HostedZoneId=zone["Id"]
                )
                for record in records["ResourceRecordSets"]:
                    if (
                            record["Type"] in ("CNAME", "A")
                            and record["Name"][:-1] == domain_name
                    ):
                        return record

        except Exception as e:
            return None

        ##
        # Old, automatic logic.
        # If re-introduced, should be moved to a new function.
        # Related ticket: https://github.com/Miserlou/Zappa/pull/458
        ##

        # We may be in a position where Route53 doesn't have a domain,
        # but the API Gateway does.
        # We need to delete this before we can create the new Route53.
        # try:
        #     api_gateway_domain = self.apigateway_client.get_domain_name(
        #     domainName=domain_name)
        #     self.apigateway_client.delete_domain_name(domainName=domain_name)
        # except Exception:
        #     pass

        return None

    def get_hosted_zone_id_for_domain(self, domain):
        """
        Get the Hosted Zone ID for a given domain.

        """
        all_zones = self.get_all_zones()
        return self.get_best_match_zone(all_zones, domain)

    @staticmethod
    def get_best_match_zone(all_zones, domain):
        """Return zone id which name is closer matched with domain name."""

        # Related: https://github.com/Miserlou/Zappa/issues/459
        public_zones = [
            zone
            for zone in all_zones["HostedZones"]
            if not zone["Config"]["PrivateZone"]
        ]

        zones = {
            zone["Name"][:-1]: zone["Id"]
            for zone in public_zones
            if zone["Name"][:-1] in domain
        }
        if zones:
            keys = max(
                zones.keys(), key=lambda a: len(a)
            )  # get longest key -- best match.
            return zones[keys]
        else:
            return None

    def set_dns_challenge_txt(self, zone_id, domain, txt_challenge):
        """
        Set DNS challenge TXT.
        """
        print("Setting DNS challenge..")
        resp = route53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch=self.get_dns_challenge_change_batch(
                "UPSERT", domain, txt_challenge
            ),
        )

        return resp

    def remove_dns_challenge_txt(self, zone_id, domain, txt_challenge):
        """
        Remove DNS challenge TXT.
        """
        print("Deleting DNS challenge..")
        resp = route53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch=self.get_dns_challenge_change_batch(
                "DELETE", domain, txt_challenge
            ),
        )

        return resp

    @staticmethod
    def get_dns_challenge_change_batch(action, domain, txt_challenge):
        """
        Given action, domain and challenge, return a change batch to use with
        route53 call.

        :param action: DELETE | UPSERT
        :param domain: domain name
        :param txt_challenge: challenge
        :return: change set for a given action, domain and TXT challenge.
        """
        return {
            "Changes": [
                {
                    "Action": action,
                    "ResourceRecordSet": {
                        "Name": "_acme-challenge.{0}".format(domain),
                        "Type": "TXT",
                        "TTL": 60,
                        "ResourceRecords": [
                            {"Value": '"{0}"'.format(txt_challenge)}],
                    },
                }
            ]
        }
