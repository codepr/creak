
from creakframework import CreakFramework

class Plugin(CreakFramework):

    def init_plugin(self):
        self.required_params['name'] = True

    def run(self, kwargs):
        print("Hello %s" % kwargs['name'])
