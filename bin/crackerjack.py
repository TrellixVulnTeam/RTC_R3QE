from inspect import getdoc

from click import command, help_option, option


def crackerjack_it(fn, comments=False, interactive=False):
    docs = list()
    for o in dir(fn):
        doc = getdoc(o)
        print(doc)
        docs.append(doc)
    with open(fn, "w+") as f:
        text = f.read()
        for doc in docs:
            text = text.replace(doc, "")
        print(text)
        # f.seek(0)
        # f.write(text)
        # f.close()


@command()
@help_option("-h", is_flag=True, help="help")
@help_option("-c", is_flag=True, help="remove comments")
@help_option("-i", is_flag=True, help="interactive")
@option("-f", help="crackerjack format: -f [module]")
def crackerjack(f, c, i):
    options = dict()
    if c:
        options["comments"] = c
    if i:
        options["interactive"] = i
    if f:
        crackerjack_it(f, **options)
