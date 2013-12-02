# Copyright (C) 2013 David Maciejak
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django import template

register = template.Library()

@register.filter(name="human_time_duration")
def human_time_duration(value): 
	"""Convert time length to human readable time.
	@param value: the value to convert.
	"""    
	mins, secs = divmod(value, 60)
	if value >= 3600:
		return '%d h %d min %d s' % (hours, mins, secs)
	else:
		return '%d min %d s' % (mins, secs)

@register.filter(name="human_file_size")
def human_file_size(value):
	"""Convert bytes size to human readable size.
	@param value: the value to convert.
	"""    
	for x in ['bytes','KB','MB','GB']:
		if value < 1024.0 and value > -1024.0:
			return "%3.1f %s" % (value, x)
		value /= 1024.0
	return "%3.1f %s" % (value, 'TB')