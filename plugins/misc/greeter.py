
from creak.baseplugin import BasePlugin

class Plugin(BasePlugin):

    """ A plugin that doesn't do much, hust greet the user """

    def init_plugin(self):
        self._set_info(
            author='codep',
            version='1.0',
            description='Greets the user')
        self._set_required_params(name=False)

    def run(self, kwargs):
        """ I don't do a lot """
        if 'name' not in kwargs:
            kwargs['name'] = 'stranger'
        print("Hello %s" % kwargs['name'])
