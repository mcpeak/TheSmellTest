from core import utils
import yara

RULE_PATH = 'rules'

def _parse_metadata(yara_file):
    kv = {}
    capturing = False
    with open(yara_file) as f:
        for line in f:
            if line.strip() == "meta:":
                capturing = True
                continue
            if capturing:
                ls = line.split('=')
                if len(ls) == 2:
                    kv[ls[0].strip()] = ls[1].strip().replace('"', '')
                else:
                    break
    return kv

class YaraHandler():
    def __init__(self):
        ruleset = {'line': {},
                   'file': {}
                  }

        for f in utils.discover_files(RULE_PATH):
            metadata = _parse_metadata(f.path)
            #TODO - add exclusion logic for specific test IDs

            # unique rule name needed for compilation, use filename with /
            # replace with . and without the yar extension
            rule_name = f.path.split('.')[0].replace('/', '.')

            if metadata.get('scantype') == 'line':
                ruleset['line'][rule_name] = f.path
            elif metadata.get('scantype') == 'file':
                ruleset['file'][rule_name] = f.path

        self._line_rules = yara.compile(filepaths = ruleset['line'])
        self._file_rules = yara.compile(filepaths = ruleset['file'])

    def match_file(self, f_path):
        with open(f_path, 'r', encoding='utf-8') as f:
            try:
                matches = self._file_rules.match(data=f.read())
            except UnicodeDecodeError as e:
                #TODO: is returning None the best thing to do?
                matches = None
        return matches

    def match_line(self, line):
        return self._line_rules.match(data=line)
