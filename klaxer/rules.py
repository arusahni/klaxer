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
        if 'message' not in self._config[service]:
            self._config[service]['message'] = {}

        if 'title' not in self._config[service]:
            self._config[service]['title'] = {}

        self._classification_rules[service] = []
        self._exclusion_rules[service] = []
        self._enrichment_rules[service] = []
        self._routing_rules[service] = []

        self._build_classification_rules(service, 'message')
        self._build_classification_rules(service, 'title')

        self._build_exclusion_rules(service, 'message')
        self._build_exclusion_rules(service, 'title')

        self._build_enrichment_rules(service, 'message')
        self._build_enrichment_rules(service, 'title')

        self._build_routing_rules(service, 'message')
        self._build_routing_rules(service, 'title')

        # Ensure that required rule sets are defined
        if not self._classification_rules:
            raise ConfigurationError(f'classification rules not defined for {service}')

        if not self._routing_rules:
            raise ConfigurationError(f'routes not defined for {service}')

    def _classify(self, alert, source, cfg):
        """Return the classification level for an alert given the defined config

        :param alert: The alert object to be classified
        :param source: The source field from the Alert object that will be used
        :param cfg: The service configuration for the type of Alert being classified
        :returns: IntEnum - Severity object
        """
        if any(crit in getattr(alert, source).lower() for crit in
               cfg['classification'].get('CRITICAL', [])):
            return Severity.CRITICAL
        elif any(warn in getattr(alert, source).lower() for warn in
                 cfg['classification'].get('WARNING', [])):
            return Severity.WARNING
        elif any(ok in getattr(alert, source).lower() for ok in
                 cfg['classification'].get('OK', [])):
            return Severity.OK
        else:
            return Severity.UNKNOWN

    def _build_classification_rules(self, service, source):
        """Build the classification rule set for a service

        :param service: The service for which rule sets will be generated
        :param source: The source field from the Alert object that will be used
        :returns: None
        """
        service = service.lower()
        cfg = self._config[service][source]

        # Default to returning UNKNOWN severity
        if 'classification' not in cfg:
            self._classification_rules[service].append(lambda x: Severity.UNKNOWN)
            return

        self._classification_rules[service].append(lambda x, src=source, cfg=cfg:
                                                   self._classify(x, src, cfg))

    def _build_exclusion_rules(self, service, source):
        """Build the exclusion rule set for a service

        :param service: The service for which rule sets will be generated
        :returns: None
        """
        service = service.lower()
        cfg = self._config[service][source]

        if 'exclude' not in cfg:
            return

        self._exclusion_rules[service].append(
            lambda x, cfg=cfg: any(ignore in getattr(x, source).lower() for ignore in cfg['exclude'])
        )

    def _build_enrichment_rules(self, service, source):
        """Build the enrichment rule set for a service

        :param service: The service for which rule sets will be generated
        :returns: None
        """
        service = service.lower()
        cfg = self._config[service][source]

        if 'enrichments' not in cfg:
            return

        if isinstance(cfg['enrichments'], str):
            self._enrichment_rules[service].append(
                lambda x, cfg=cfg: {source: cfg['enrichments'].format(getattr(x, source))}
            )
        elif isinstance(cfg['enrichments'], list):
            for e in cfg['enrichments']:
                self._enrichment_rules[service].append(
                    lambda x, e=e: {source: e['THEN'].format(getattr(x, source))} if e['IF'].lower() in getattr(x, source).lower() else None
                )
        else:
            raise ConfigurationError(f'Invalid enrichments definition for {service}')

    def _build_routing_rules(self, service, source):
        """Build the routing rule set for a service

        :param service: The service for which rule sets will be generated
        :returns: None
        """
        service = service.lower()
        cfg = self._config[service][source]

        if 'routes' not in cfg:
            return

        if isinstance(cfg['routes'], str):
            self._routing_rules[service].append(
                lambda x, cfg=cfg: cfg['routes']
            )
        elif isinstance(cfg['routes'], list):
            for r in cfg['routes']:
                self._routing_rules[service].append(
                    lambda x, r=r: r['THEN'] if r['IF'].lower() in getattr(x, source).lower() else None
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

