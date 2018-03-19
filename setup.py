from setuptools import setup

setup(name='lorawan-parser',
      version='0.1',
      description='LoRaWAN packet parser',
      url='http://github.com/DurandA/lorawan-parser',
      author='Arnaud Durand',
      author_email='arnaud.durand@live.com',
      license='MIT',
      packages=['lorawan'],
      install_requires=[
          'cryptography',
      ],
      zip_safe=False)
