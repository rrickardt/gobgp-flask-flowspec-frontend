from flask import Flask, flash, redirect, render_template, \
     request, url_for
import os
import subprocess
import re
import json
import itertools as it
app = Flask(__name__)

@app.route("/")
def hello():
    return redirect(url_for('routes'))

@app.route('/login/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != app.config['USERNAME']:
            error = 'Invalid username'
        elif request.form['password'] != app.config['PASSWORD']:
            error = 'Invalid password'
        else:
            session['logged_in'] = True
            flash('You were logged in')
            return redirect(url_for('showroutes'))
    return render_template('login.html', error=error)

@app.route('/logout/')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('showroutes'))

def convertFlag(flag):
    flags = {'C':128,'E':64,'U':32, 'A':16, 'P':8, 'R':4, 'S':2, 'F':1}
#invert flags dictionary, because we need look up by number value
    flags = {v:k for k, v in flags.items()}
#iterate to have all combinations of flags
    for i in range(1,len(flags)+1):
        combs = list(it.combinations(flags.items(),i))
#no need for list of all combinations, just match the first that fits
        for com in combs:
            kas = sum([k for k,v in com])
            ves = ([v for k,v in com])
            if kas == flag:
              return ''.join(ves)

def showroutes():

    test=subprocess.Popen(['/usr/local/bin/gobgp', 'global', 'rib', '-a' ,'ipv4-l3vpn-flowspec', '-j'], stdout=subprocess.PIPE)
    entries, err = test.communicate()
    routes = json.loads(entries)
    out=[]
#    dstip = srcip = srcport = dstport = proto = itype = icode = 'None'
    for route in  routes:
       dstip = srcip = srcportstart = srcportend = dstportstart = dstportend = proto = itype = icode = plenstart = plenend = dscp = fragtype = tcpflags = 'None'
       rd =  str(routes[route][0]['attrs'][1]['value'][0]['rd']['admin'])  + str(":") + str(routes[route][0]['attrs'][1]['value'][0]['rd']['assigned'])
       for base in routes[route][0]['attrs'][1]['value'][0]['value']:
          #print base['type']
          if base['type'] == 1:
             dstip = base['value']['prefix']
             #dstip = str(dstip)
          if base['type'] == 2:
             srcip = base['value']['prefix']
             #srcip = str(srcip)
          if base['type'] == 3:
             proto = base['value'][0]['value']
             if proto == 6:
                 proto = 'tcp'
             if proto == 17:
                 proto = 'udp'
             if proto == 1:
                 proto = 'icmp'
#So, there is range supported at and i need for srcport, dstport, packet length
#After discussion, there should be just one LTEQ GTEQ pair of values, so let`s hardcode it as start and end
#I am implicitly assuming that first value is lower boundary and second value is higher boundary

          if base['type'] == 5:
             dstportstart = base['value'][0]['value']
             dstportstart = str(dstportstart)
             try:
               dstportend = base['value'][1]['value']
               dstportend = str(dstportend)
             except:
               dstportend = 'None'
#this is just for compatibility with one-value version
             #dstport = dstportstart
          if base['type'] == 6:
#             print base['value']
             srcportstart = base['value'][0]['value']
             srcportstart = str(srcportstart)
             try:
               srcportend = base['value'][1]['value']
               srcportend = str(srcportend)
             except:
               srcportend = 'None'
             #srcport = srcportstart
          if base['type'] == 7:
             itype = base['value'][0]['value']
             itype = str(itype)
          if base['type'] == 8:
             icode = base['value'][0]['value']
             icode = str(icode)
          if base['type'] == 9:
             tcpflags = base['value'][0]['value']
	     tcpflags = convertFlag(tcpflags)
#this static mapping is deprecated because there can be multiple combined values
#in this case convertFlag solves this
#             if tcpflags == 1:
#                 tcpflags = 'F'
#             if tcpflags == 2:
#                 tcpflags = 'S'
#             if tcpflags == 4:
#                 tcpflags = 'R'
#             if tcpflags == 8:
#                 tcpflags = 'P'
#             if tcpflags == 16:
#                 tcpflags = 'A'
#             if tcpflags == 32:
#                 tcpflags = 'U'
#             if tcpflags == 64:
#                 tcpflags = 'E'
#             if tcpflags == 128:
#                 tcpflags = 'C'
          if base['type'] == 10:
             plenstart = str(base['value'][0]['value'])
             try:
               plenend = str(base['value'][1]['value'])
             except:
               plenend = 'None'
             #plen = plenstart
          if base['type'] == 11:
             dscp =  str(base['value'][0]['value'])
          if base['type'] == 12:
             fragtype =  base['value'][0]['value']
             if fragtype == 0:
                 fragtype = 'not-a-fragment'
             if fragtype == 1:
                 fragtype = 'dont-fragment'
             if fragtype == 2:
                 fragtype = 'is-fragment'
             if fragtype == 4:
                 fragtype = 'first-fragment'
             if fragtype == 8:
                 fragtype = 'last-fragment'
 
   #action discard = rate limit 0
       try: 
    #type 128, rate 0 is discard, rate 9600 je shape
         value = routes[route][0]['attrs'][2]['value'][0]['rate']
       except:
         value = routes[route][0]['attrs'][2]['value'][0]['value']
       type = routes[route][0]['attrs'][2]['value'][0]['subtype']
       action = "unknown"
       if value == 0 and type == 6:
         action = "discard"
       if value != 0 and type == 6:
         action = "rate-limit" +  " " + str(value)
       if value != 0 and type == 9:
         action = "mark" + " " + str(value)
       if value != 0 and type == 8:
         action = "redirect" + " " + str(value)
#       out.append({'rd':rd, 'dstip':dstip, 'action':action, 'srcip':srcip, 'proto':proto, 'srcport':srcport, 'dstport':dstport, 'itype':itype, 'icode':icode, 'tcpflags':tcpflags, 'fragtype':fragtype, 'plen':plen, 'dscp':dscp})
       out.append({'rd':rd, 'dstip':dstip, 'action':action, 'srcip':srcip, 'proto':proto, 'srcportstart':srcportstart,'srcportend':srcportend, 'dstportstart':dstportstart, 'dstportend':dstportend, 'itype':itype, 'icode':icode, 'tcpflags':tcpflags, 'fragtype':fragtype, 'plenstart':plenstart, 'plenend':plenend, 'dscp':dscp})


     # print out#['srcport']
    return out
@app.route("/routes/")
def routes():
    routes = showroutes() 
#    print routes
    return render_template('show_entries.html', entries=routes)

@app.route("/routedel/<routeid>")
def routedel(routeid):
    routes = showroutes()
    routeid = int(routeid)
    delroute = routes[routeid]
    print delroute
#format is ([rd, dstip, srcip, proto, srcport, dstport, action])
#gobgp global rib -a flowvpn4 del rd 28952:2 match  source 3.2.1.4/32 destination 216.58.201.99/32 protocol tcp source-port 3343 destination-port 443 then discard
    rd = delroute['rd']
    dstip = str(delroute['dstip'])
    action = delroute['action']
#    if delroute['srcip'] != 'None':
#        srcip = delroute['srcip']
#    if delroute['srcport'] != 'None':
#        srcport = delroute['srcport']
#    if delroute['dstport'] != 'None':
#        dstport = str(delroute['dstport'])
#    if delroute['proto'] != 'None':
#        proto = delroute['proto']

#Mandatory parameters should be dstip, action, rt/rd
    skelcmd = ['gobgp', 'global', 'rib', '-a', 'ipv4-l3vpn-flowspec', 'del', 'rd', rd, 'match', 'destination', dstip]
    action = action.split()
    try:
       act = action[0]
       actparm = action[1]
       endcmd = [ 'then', act, actparm, 'rt', rd]
    except:
       endcmd = [ 'then', action[0], 'rt', rd]
#    endcmd = [ 'then', action]
#    delcmd = skelcmd + endcmd

    body = []
    if delroute['srcip'] != 'None':
       body = ['source', delroute['srcip']]
    
    if delroute['srcportstart'] != 'None' and delroute['srcportend'] != 'None':
       if body:
          body = body + ['source-port', '>=' + delroute['srcportstart'] + '&<=' + delroute['srcportend']]
       else:
          body = ['source-port', '>=' + delroute['srcportstart'] + '&<=' + delroute['srcportend']]
    if delroute['srcportstart'] != 'None' and delroute['srcportend'] == 'None':
       if body:
          body = body + ['source-port', delroute['srcportstart']]
       else:
          body = ['source-port', delroute['srcportstart']]

    if delroute['dstportstart'] != 'None' and delroute['dstportend'] != 'None':
       if body:
          body = body + ['destination-port', '>=' + delroute['dstportstart'] + '&<=' + delroute['dstportend']]
       else:
          body = ['destination-port', '>=' + delroute['dstportstart'] + '&<=' + delroute['dstportend']]

    if delroute['dstportstart'] != 'None' and delroute['dstportend'] == 'None':
       if body:
          body = body + ['destination-port', delroute['dstportstart']]
       else:
          body = ['destination-port', delroute['dstportstart']]
    if delroute['proto'] != 'None':
       if body:
          body = body + ['protocol', str(delroute['proto'])]
       else:
          body = ['protocol', str(delroute['proto'])]
    if delroute['icode'] != 'None':
       if body:
          body = body + ['icmp-code', delroute['icode']]
       else:
          body = ['icmp-code', delroute['icode']]
    if delroute['itype'] != 'None':
       if body:
          body = body + ['icmp-type', delroute['itype']]
       else:
          body = ['icmp-type', delroute['itype']]
    if delroute['tcpflags'] != 'None':
       if body:
          body = body + ['tcp-flags', delroute['tcpflags']]
       else:
          body = ['tcp-flags', delroute['tcpflags']]
    if delroute['fragtype'] != 'None':
       if body:
          body = body + ['fragment', delroute['fragtype']]
       else:
          body = ['fragment', delroute['fragtype']]
    if delroute['dscp'] != 'None':
       if body:
          body = body + ['dscp', delroute['dscp']]
       else:
          body = ['dscp', delroute['dscp']]

    if delroute['plenstart'] != 'None' and delroute['plenend'] != 'None':
       if body:
          body = body + ['packet-length', '>=' + delroute['plenstart'] + '&<=' + delroute['plenend']]
       else:
          body = ['packet-length', '>=' + delroute['plenstart'] + '&<=' + delroute['plenend']]

    if delroute['plenstart'] != 'None' and delroute['plenend'] == 'None':
       if body:
          body = body + ['packet-length', delroute['plenstart']]
       else:
          body = ['packet-length', delroute['plenstart']]
#
#
#

#

#
#
#    print body
#    addcmd =  ['gobgp', 'global', 'rib', '-a', 'flowvpn4', 'add', 'rd', rd, 'match', 'destination', dstip, 'then', action, 'rt', rd]
    delcmd = skelcmd + endcmd
    if body:
       delcmd = skelcmd + body + endcmd
    print delcmd

#    action = delroute[6]
#    print action
    
#    if 'redirect' in action:
#       action_cmd = action.split(":",1)[1]
#       action = 'redirect'
#    elif 'mark' in action:
#       action_cmd = action.split(":",1)[1]
#       action = 'mark'
#    elif 'rate' in action:
#       action_cmd = action.split(":",1)[1].split(".")[0]
#       action = 'rate-limit'
#    elif 'discard' in action:
#       action = 'discard'
#    print action
    #print action_cmd
#    if action == 'discard':
#       delcmd = ['gobgp', 'global', 'rib', '-a', 'flowvpn4', 'del', 'rd', rd, 'match', 'source', srcip, 'source-port', srcport, 'destination', dstip, 'destination-port', dstport, 'protocol', proto, 'then', action]
#    else:
#       delcmd = ['gobgp', 'global', 'rib', '-a', 'flowvpn4', 'del', 'rd', rd, 'match', 'source', srcip, 'source-port', srcport, 'destination', dstip, 'destination-port', dstport, 'protocol', proto, 'then', action, action_cmd]
#       print action_cmd
    subprocess.call(delcmd)
    return redirect(url_for('routes'))


@app.route("/routeadd/", methods=['POST'])
def routeadd():
#    if not session.get('logged_in'):
#        abort(401)
#    rd = dstip = srcip = proto = srcportstart = srcportend = dstportstart = dstportend = icode = itype = plenstart = plenend = dscp = fragtype = action = 'None'
    rd = str(request.form['rd'])
    dstip = request.form['dstip']
    srcip = request.form['srcip']
    proto = request.form['proto']
    srcportstart = request.form['srcportstart']
    srcportend = request.form['srcportend']
    dstportstart = request.form['dstportstart']
    dstportend = request.form['dstportend']
    icode = request.form['icode']
    itype = request.form['itype']
#    tcpflags = request.form['tcpflags']
    plenstart = request.form['plenstart']
    plenend = request.form['plenend']
    dscp = request.form['dscp']
    fragtype = request.form['fragtype']
    action = request.form['action']
    tflags = request.form.getlist('tflags')
    tcpflags = ''.join(tflags).upper()
    
    if action != 'discard':
       action = action + ' ' + request.form['action_cmd']
    #addcmd = ['gobgp', 'global', 'rib', '-a', 'flowvpn4', 'add', 'rd', rd, 'match', 'source', srcip, 'source-port', srcport, 'destination', dstip, 'destination-port', dstport, 'protocol', proto, 'then', action]

#Mandatory parameters should be dstip, action, rt/rd
    skelcmd = ['gobgp', 'global', 'rib', '-a', 'ipv4-l3vpn-flowspec', 'add', 'rd', rd, 'match', 'destination', dstip]
    action = action.split()
    try:
       act = action[0]
       actparm = action[1]
       endcmd = [ 'then', act, actparm, 'rt', rd]
    except:
       endcmd = [ 'then', action[0], 'rt', rd]
    addcmd = skelcmd + endcmd

    body = []
    if srcip:
        body = ['source', srcip]
#everything is unicode string, something or empty
    if srcportstart and not srcportend:
      print 'start is nonempty and end is empty'
      srcportend = srcportstart
      if body:
        body = body + ['source-port', '>=' + srcportstart + '&<=' + srcportend]
      else:
        body = ['source-port', '>=' + srcportstart + '&<=' + srcportend]
      srcportend = ''
    if not srcportstart and srcportend:
      print 'start is empty and end is nonempty'
      srcportstart = srcportend
      if body:
        body = body + ['source-port', '>=' + srcportstart + '&<=' + srcportend]
      else:
        body = ['source-port', '>=' + srcportstart + '&<=' + srcportend]
      srcportstart = ''
    if srcportstart and srcportend:
      print 'start is nonempty and end is nonempty'
#these are unicode strings, so converting to int to compare
      if int(srcportend) < int(srcportstart):
        tempsrcportstart = srcportstart
        tempsrcportend = srcportend
        srcportstart = tempsrcportend
        srcportend = tempsrcportstart
      if body:
        body = body + ['source-port', '>=' + srcportstart + '&<=' + srcportend]
      else:
        body = ['source-port', '>=' + srcportstart + '&<=' + srcportend]

    if dstportstart and not dstportend:
      print 'start is nonempty and end is empty'
      dstportend = dstportstart
      if body:
        body = body + ['destination-port', '>=' + dstportstart + '&<=' + dstportend]
      else:
        body = ['destination-port', '>=' + dstportstart + '&<=' + dstportend]
      dstportend = ''
    if not dstportstart and dstportend:
      print 'start is empty and end is nonempty'
      dstportstart = dstportend
      if body:
        body = body + ['destination-port', '>=' + dstportstart + '&<=' + dstportend]
      else:
        body = ['destination-port', '>=' + dstportstart + '&<=' + dstportend]
      dstportstart = ''
    if dstportstart and dstportend:
      print 'start is nonempty and end is nonempty'
#these are unicode strings, so converting to int to compare
      if int(dstportend) < int(dstportstart):
        tempdstportstart = dstportstart
        tempdstportend = dstportend
        dstportstart = tempdstportend
        dstportend = tempdstportstart
      if body:
        body = body + ['destination-port', '>=' + dstportstart + '&<=' + dstportend]
      else:
        body = ['destination-port', '>=' + dstportstart + '&<=' + dstportend]

    if proto:
        if body:
          body = body + ['protocol', proto]
        else:
          body = ['protocol', proto]
    if itype:
        if body:
          body = body + ['icmp-type', itype]
        else:
          body = ['icmp-type', itype]
    if icode:
        if body:
          body = body + ['icmp-code', icode]
        else:
          body = ['icmp-code', icode]
    if fragtype:
        if body:
          body = body + ['fragment', fragtype]
        else:
          body = ['fragment', fragtype]

    if plenstart and not plenend:
      print 'start is nonempty and end is empty'
      plenend = plenstart
      if body:
        body = body + ['packet-length', '>=' + plenstart + '&<=' + plenend]
      else:
        body = ['packet-length', '>=' + plenstart + '&<=' + plenend]
      plenend = ''
    if not plenstart and plenend:
      print 'start is empty and end is nonempty'
      plenstart = plenend
      if body:
        body = body + ['packet-length', '>=' + plenstart + '&<=' + plenend]
      else:
        body = ['packet-length', '>=' + plenstart + '&<=' + plenend]
      plenstart = ''
    if plenstart and plenend:
      print 'start is nonempty and end is nonempty'
#these are unicode strings, so converting to int to compare
      if int(plenend) < int(plenstart):
        tempplenstart = plenstart
        tempplenend = plenend
        plenstart = tempplenend
        plenend = tempplenstart
      if body:
        body = body + ['packet-length', '>=' + plenstart + '&<=' + plenend]
      else:
        body = ['packet-length', '>=' + plenstart + '&<=' + plenend]

    if dscp:
        if body:
          body = body + ['dscp', dscp]
        else:
          body = ['dscp', dscp]
    if tcpflags:
        if body:
         body = body + ['tcp-flags', tcpflags]
        else:
          body = ['tcp-flags', tcpflags]
#
#
#
#    print body
#    addcmd =  ['gobgp', 'global', 'rib', '-a', 'flowvpn4', 'add', 'rd', rd, 'match', 'destination', dstip, 'then', action, 'rt', rd]
    addcmd = skelcmd + endcmd
    if body:
       addcmd = skelcmd + body + endcmd
    print addcmd
    subprocess.call(addcmd)
#    flash('New flowspec entry was successfully installed')
    return redirect(url_for('routes'))
#    pass

if __name__ == "__main__":
    app.run()

