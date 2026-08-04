"""Intake: the declared fact base a review is built on."""

from .questionnaire import QUESTIONS, blank_form, load_intake, parse_intake

__all__ = ["QUESTIONS", "blank_form", "load_intake", "parse_intake"]
