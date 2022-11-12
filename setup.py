'''setup fluxvault package'''
from setuptools import setup

setup(name='fluxvault',
      version='1.0',
      description='Flux Vault Node Agent',
      long_description='Flux Vault a distributed agent to load secrets into a Flux App',
      license="MIT",
      author='Tom Moulton',
      author_email='tom@moulton.us',
      url='https://github.com/RunOnFlux/FluxVault.git',
      packages=['fluxvault'],
      install_requires=['pycryptodome'] #external packages as dependencies
)
