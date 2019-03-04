from dataclasses import dataclass

from boto3 import resource

from .dynamodb import DynamoDB
from .events import Events
from .route53 import Route53
from .sns import SNS
from .utils import (ppformat, pprint)

for p in [pprint, ppformat]:
    pass


# logging.basicConfig(format="%(levelname)s:%(message)s")
# logger = logging.getLogger(__name__)
# logger.setLevel(logging.INFO)


@dataclass
class Zappa(Events, DynamoDB, SNS, Route53):

    def __post_init__(self):
        self.cloudwatch = resource('cloudwatch')

    def shell(self):
        """
        Spawn a PDB shell.
        """
        import pdb

        pdb.set_trace()
