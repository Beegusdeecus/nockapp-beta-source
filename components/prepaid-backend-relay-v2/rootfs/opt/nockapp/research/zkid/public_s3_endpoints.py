"""Public, image-owned endpoint validation; standard library only for parent relays."""
import re


def s3_host(region,bucket):
    if type(region) is not str or not re.fullmatch(r'[a-z]{2}-[a-z]+-[1-9]',region):
        raise ValueError('public-s3-region')
    if (type(bucket) is not str or not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]',bucket)
        or bucket.startswith(('xn--','sthree-','amzn-s3-demo-'))
        or bucket.endswith(('-s3alias','--ol-s3','--x-s3','--table-s3'))):raise ValueError('public-s3-bucket')
    return bucket+'.s3.'+region+'.amazonaws.com'


def replicas(rows):
    if type(rows) is not list or not 2<=len(rows)<=4:raise ValueError('public-s3-replicas')
    for row in rows:
        if (type(row) is not dict or set(row)!={'name','region','bucket'} or type(row['name']) is not str
            or not re.fullmatch(r'[a-z0-9][a-z0-9-]{2,63}',row['name'])):raise ValueError('public-s3-replicas')
        s3_host(row['region'],row['bucket'])
    if len({r['name'] for r in rows})!=len(rows) or len({r['region'] for r in rows})!=len(rows):
        raise ValueError('public-s3-independence')
    return rows
