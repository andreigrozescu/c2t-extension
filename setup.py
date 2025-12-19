from setuptools import setup, find_packages

setup(
    name='c2t',
    version='1.0.0',
    description='C2T: Containters to Triples Extension.',
    author='Andrei Iulian Grozescu',
    
    packages=find_packages(),
    
    include_package_data=True,

    install_requires=[
        'click',           
        'rdflib',          
        'morph-kgc',       
        'pandas',          
        'pyyaml',         
    ],
    
    entry_points='''
        [console_scripts]
        c2t=src.CLI:cli
    ''',

    python_requires='>=3.8',
)
