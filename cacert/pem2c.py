f_in = open('cacert.pem', 'r')
f_out = open('cacert.h', 'w')

data = f_in.read()
data_s = data.split('\n\n')

f_out.write('const char *CACERT[] = {\n')

for cert in data_s:
	cert_f = cert.replace('\n', '\\n"\n\t"')
	f_out.write('\t"%s\\n",\n\n' % cert_f)

f_out.write('};\n')

f_out.close()
