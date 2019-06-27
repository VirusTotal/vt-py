---
title: Getting started
weight: 5
pre: "<b>1. </b>"
chapter: false
---

## Requirements

**vt-py** requires Python 3.5.6+, Python 2.x is not supported. This is because **vt-py** makes use of the new [**async/await**](https://snarky.ca/how-the-heck-does-async-await-work-in-python-3-5/) syntax for implementing asynchronous coroutines. Not supporting Python 2.x was a difficult decission to make, as we are aware that Python 2.x is still popular among VirusTotal users, but in the long run we think it's the right one. Python 2.7 has its days numbered, and the new concurrency features in included in Python 3.5+ are perfect for creating highly performant code without having to deal with multithreading or multiprocessing.

## How to install

The easiest way of installing **vt-py** is using **pip**:

```shell
pip install vt-py
```
