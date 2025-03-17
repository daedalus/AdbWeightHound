from setuptools import setup, find_packages

setup(
    name="TheBrainCollector",
    version="0.1",
    packages=find_packages(),
    install_requires=[line.strip() for line in open('requirements.txt','r')],
    entry_points={
        'console_scripts': [
            'thebraincollector=src.main:main',  # Modify if you have a main() function
        ],
    },
    author="Darío Clavijo",
    author_email="clavijodario@gmail.com",
    description="The Brain Collector - A tool to scan and analyze ML models and APK files.",
    license="MIT",
    keywords="ML models APK scanner",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
)

