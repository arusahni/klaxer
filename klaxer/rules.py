import yaml
from klaxer.models import Severity
from klaxer.errors import ServiceNotDefinedError, ConfigurationError


class Rules:
    def __init__(self):
        self._classification_rules = {}
        self._exclusion_rules = {}
        self._enrichment_rules = {}
        self._routing_rules = {}
        self._config = None

        try:
            # TODO: Absolute path? Where should this live?
            with open('config/klaxer.yml', 'r') as ymlfile:
                self._config = yaml.load(ymlfile)
        except yaml.YAMLError as ye:
            raise ConfigurationError('failed to parse config') from ye

        for section in self._config:
            # Subsequent definitions of the same service will overwrite the
            # previous ones.
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

        # This is a required setting
        if 'classification' not in cfg:
            raise ConfigurationError(f'classification rules not defined for {service}')

        self._classification_rules[service] = []
        self._classification_rules[service].append(
            lambda x, cfg=cfg: Severity.CRITICAL if any(crit in x.message.lower() for crit in
                                            cfg['classification'].get('CRITICAL', []))
                    else Severity.WARNING if any(warn in x.message.lower() for warn in
                                            cfg['classification'].get('WARNING', []))
                    else Severity.OK if any(ok in x.message.lower() for ok in
                                            cfg['classification'].get('OK', []))
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

        # This is an optional setting
        if 'exclude' not in cfg:
            return

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

        # This is an optional setting
        if 'enrichments' not in cfg:
            return

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
            raise ConfigurationError(f'Invalid enrichments definition for {service}')

    def _build_routing_rules(self, service):
        """Build the routing rule set for a service

        :param service: The service for which rule sets will be generated
        :returns: None
        """
        service = service.lower()
        cfg = self._config[service]

        # This is a required setting
        if 'routes' not in cfg:
            raise ConfigurationError(f'routes not defined for {service}')

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
            raise ConfigurationError(f'invalid routes definition for {service}')

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

