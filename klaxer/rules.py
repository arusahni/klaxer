import yaml

from klaxer.models import Severity
from klaxer.errors import ServiceNotDefinedError


class Rules:
    def __init__(self):
        self._classification_rules = {}
        self._exclusion_rules = {}
        self._enrichment_rules = {}
        self._routing_rules = {}
        self._config = None

        # TODO: Absolute path? Where should this live?
        with open('config/klaxer.yml', 'r') as ymlfile:
            self._config = yaml.load(ymlfile)

        for section in self._config:
            # TODO: Check if rules have already been defined for this section's
            # service.
            self._build_rules(section)


    def _build_rules(self, service):
        """Build the rules sets for classification, exclusion, enrichment and
        routing for each service.

        :param service: The service for which rule sets will be generated
        :returns: None
        """
        self._build_classification_rules(service)
        self._build_exclusion_rules(service)
        self._build_enrichment_rules(service)
        self._build_routing_rules(service)

    def _build_classification_rules(self, service):
        """Build the classification rule set for a service

        :param service: The service for which rule sets will be generated
        :returns: None
        """
        service = service.lower()
        cfg = self._config[service]
        self._classification_rules[service] = []
        self._classification_rules[service].append(
            lambda x, cfg=cfg: Severity.CRITICAL if any(crit in x.message.lower() for crit in
                                            cfg['classification']['CRITICAL'])
                    else Severity.WARNING if any(warn in x.message.lower() for warn in
                                            cfg['classification']['WARNING'])
                    else Severity.UNKNOWN
        )

    def _build_exclusion_rules(self, service):
        """Build the exclusion rule set for a service

        :param service: The service for which rule sets will be generated
        :returns: None
        """
        service = service.lower()
        cfg = self._config[service]
        self._exclusion_rules[service] = []
        self._exclusion_rules[service].append(
            lambda x, cfg=cfg: any(ignore in x.message.lower() for ignore in cfg['exclude'])
        )

    def _build_enrichment_rules(self, service):
        """Build the enrichment rule set for a service

        :param service: The service for which rule sets will be generated
        :returns: None
        """
        service = service.lower()
        cfg = self._config[service]
        self._enrichment_rules[service] = []

        if isinstance(cfg['enrichments'], str):
            self._enrichment_rules[service].append(
                lambda x, cfg=cfg: {'message': cfg['enrichments'].format(x.message)}
            )
        elif isinstance(cfg['enrichments'], list):
            for e in cfg['enrichments']:
                self._enrichment_rules[service].append(
                    lambda x, e=e: {'message': e['THEN'].format(x.message)} if e['IF'].lower() in x.message.lower() else None
                )
        else:
            #TODO: Error here
            pass

    def _build_routing_rules(self, service):
        """Build the routing rule set for a service

        :param service: The service for which rule sets will be generated
        :returns: None
        """
        service = service.lower()
        cfg = self._config[service]
        self._routing_rules[service] = []

        if isinstance(cfg['routes'], str):
            self._routing_rules[service].append(
                lambda x, cfg=cfg: cfg['routes']
            )
        elif isinstance(cfg['routes'], list):
            for r in cfg['routes']:
                self._routing_rules[service].append(
                    lambda x, r=r: r['THEN'] if r['IF'].lower() in x.message.lower() else None
                )
        else:
            #TODO: Error here
            pass

    def get_classification_rules(self, service):
        """Get the classification rule set for a service. This rule set will be
        a list of lambda functions which will take in the Alert object to which
        rules should be applied

        :param service: The name of the service
        :returns: None
        """
        try:
            service = service.lower()
            return self._classification_rules[service]
        except KeyError as ke:
            raise ServiceNotDefinedError(str(ke))

    def get_exclusion_rules(self, service):
        """Get the exclusion rule set for a service. This rule set will be
        a list of lambda functions which will take in the Alert object to which
        rules should be applied

        :param service: The name of the service
        :returns: None
        """
        try:
            service = service.lower()
            return self._exclusion_rules[service]
        except KeyError as ke:
            raise ServiceNotDefinedError(str(ke))

    def get_enrichment_rules(self, service):
        """Get the enrichment rule set for a service. This rule set will be
        a list of lambda functions which will take in the Alert object to which
        rules should be applied

        :param service: The name of the service
        :returns: None
        """
        try:
            service = service.lower()
            return self._enrichment_rules[service]
        except KeyError as ke:
            raise ServiceNotDefinedError(str(ke))

    def get_routing_rules(self, service):
        """Get the routing rule set for a service. This rule set will be
        a list of lambda functions which will take in the Alert object to which
        rules should be applied

        :param service: The name of the service
        :returns: None
        """
        try:
            service = service.lower()
            return self._routing_rules[service]
        except KeyError as ke:
            raise ServiceNotDefinedError(str(ke))


if __name__ == '__main__':
    r = Rules()
    rules = r.get_routing_rules('Service')
    print(rules)
    test = "this is a keepalive bytes test"
    for rule in rules:
        print(rule(test))

