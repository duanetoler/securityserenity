---
layout: default
---
Welcome to Security Serenity — firewall engineering, routing policies, VPN
debugs, RFC compliance, and the occasional vendor accountability moment.

{% for post in site.posts %}
## [{{ post.title }}]({{ post.url }})
*{{ post.date | date: "%B %d, %Y" }}*

{{ post.excerpt }}
---
{% endfor %}
