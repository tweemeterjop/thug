#!/usr/bin/env python
from __future__ import with_statement

from HTMLElement import HTMLElement
from attr_property import attr_property
from text_property import text_property


class HTMLTextAreaElement(HTMLElement):
    defaultValue    = None

    @property
    def form(self):
        pass

    accessKey       = attr_property("accesskey")
    cols            = attr_property("cols", long)
    disabled        = attr_property("disabled", bool)
    name            = attr_property("name")
    readOnly        = attr_property("readonly", bool)
    rows            = attr_property("rows", long)
    tabIndex        = attr_property("tabindex", long)
    value           = text_property()

    @property
    def type(self):
        return "textarea"

    def focus(self):
        pass

    def blur(self):
        pass

    def select(self):
        pass

