from core.YaraHandler import YaraHandler

def main():

    yh = YaraHandler()
    print(yh.match_file('tests/private_key_false_positive'))


if __name__ == "__main__":
    main()
