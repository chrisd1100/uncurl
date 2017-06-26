f_in = open('cacert.pem', 'rb')
f_out = open('cacert.h', 'w')
data = f_in.read()

data_s = data.split('\n\n')
data_len = len(data_s)

f_out.write('#ifndef __CACERT_H\n')
f_out.write('#define __CACERT_H\n')
f_out.write('\n#define CACERT_LEN %d\n\n' % data_len)
f_out.write('const char CACERT[CACERT_LEN][3380] = {\n')

for cert in data_s:
	f_out.write('\t{\n\t\t')
	n = 0

	for b in cert:
		f_out.write('0x%02x, ' % ord(b))
		n += 1
		if n % 15 == 0: f_out.write('\n\t\t');

	f_out.write('0x00\n\t},\n')

f_out.write('};\n')
f_out.write('#endif\n')

f_out.close()
