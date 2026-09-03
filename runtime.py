
class Runtime(object):
    _instances = {}
    def __new__(class_, *args, **kwargs):
        if class_ not in class_._instances:
            class_._instances[class_] = super(Runtime, class_).__new__(class_)
        return class_._instances[class_]
    
    def __init__(self, system_mapping: dict=None, country_mapping: dict=None):
        if hasattr(self, '_initialized'):
            return None
        self._initialized = True
        self._system_mapping = system_mapping
        self._country_mapping = country_mapping
    
    @property
    def system_mapping(self):
        return self._system_mapping
    
    @property
    def country_mapping(self):
        return self._country_mapping