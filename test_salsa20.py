from salsa20 import *
import sys
import time
import os
import timeit
import datetime
from hurry.filesize import size, alternative


lokasi_hasil_test = os.path.join(os.getcwd(), 'hasil_test_salsa20')
# buat lokasi hasil test
if not os.path.exists(lokasi_hasil_test):
    os.mkdir(lokasi_hasil_test)


def main():
    if False:
        key = 'qwerty7890123456'
        # wrong_key = 'qwerty7890111111'
        nonce = '12345678'

        input_file = open(sys.argv[1], 'rb')
        input_data = input_file.read()
        input_file.close()

        plaintext = input_data

        cipher = Salsa20(key, nonce)
        t0 = time.time()
        ciphertext = cipher.encrypt(plaintext)
        t1 = time.time()

        tmpl1 = '  total time to encrypt %d bytes'
        tmpl2 = ': %6.4f secs,'
        tmpl3 = 'or about %dKB per sec'

        output_file = open(sys.argv[2], 'wb')
        output_file.write(ciphertext)
        output_file.close()
        print tmpl1 % (len(plaintext)),
        print tmpl2 % (t1 - t0),
        print tmpl3 % (len(plaintext) / ((t1 - t0) * 1000))
    if False:
        key = os.urandom(32)
        nonce = os.urandom(8)
        message = 'kucing meong'

        s20 = Salsa20(key, nonce)
        ciphertext = s20.encrypt(message)
        print(ciphertext)

        # objek Salsa20 (cipher) harus dibuat ulang
        s20 = Salsa20(key, nonce)
        # decrypt ciphertext jadi message
        print(s20.decrypt(ciphertext))


def test_enkripsi_dekirpsi_salsa20_satu_jenis_round(input_dir_path='', keysize=32, rounds=20):
    print '-' * 50
    print 'Mulai test_enkripsi_dekirpsi_salsa20_satu_round:', datetime.datetime.now()
    mulai_proses = timeit.default_timer()

    # periksa keberadaan lokasi input
    if not os.path.exists(input_dir_path):
        sys.exit("WARNING: Lokasi %s tidak ditemukan!\nPeriksa kembali lokasi tersebut lalu jalankan ulang program." % input_dir_path)

    # periksa keberadaan lokasi output
    output_dir_path = os.path.join(lokasi_hasil_test, 'satu_jenis_round')
    if os.path.exists(output_dir_path):
        sys.exit('WARNING: Folder %s sudah ada di lokasi %s\nHapus terlebih dahulu folder tersebut dan jalankan ulang program.' % ('satu_jenis_round', lokasi_hasil_test))
    else:
        os.mkdir(output_dir_path)

    # buat lokasi report
    report_dir_path = os.path.join(output_dir_path, 'report')
    os.mkdir(report_dir_path)

    list_of_filenames = next(os.walk(input_dir_path))[2]  # hanya file saja tidak termasuk directory

    nama_file_csv = 'hasil_test_enkripsi_dekripsi_salsa20_satu_jenis_round.csv'
    csv = open(os.path.join(report_dir_path, nama_file_csv), 'w')
    # tulis row title
    columnTitleRow = '{},{},{},{},{},{},{}\n'.format('No', 'File', 'ukuran file', 'waktu enkripsi', 'proses data enkripsi', 'waktu dekripsi', 'proses data dekripsi')
    csv.write(columnTitleRow)

    # proses setiap file
    for index, fn in enumerate(list_of_filenames):
        input_file_path = os.path.join(input_dir_path, fn)  # fn adalah file name
        f = open(input_file_path, 'rb')
        message = f.read()
        f.close()

        # file_type gak perlu
        # file_length = size(len(message), system=alternative)
        file_length = len(message) / 1024.0  # ubah ke dalam kilobyte/KB

        key = os.urandom(keysize)
        nonce = os.urandom(8)
        s20 = Salsa20(key, nonce)

        enc_start = timeit.default_timer()
        encrypted_message = s20.encrypt(message)
        enc_end = timeit.default_timer()
        enc_time = enc_end - enc_start
        enc_data_per_sec = len(message) / (enc_time * 1024)  # KB per detik

        # cipherfile_length = size(len(encrypted_message), system=alternative)

        s20 = Salsa20(key, nonce)
        dec_start = timeit.default_timer()
        decrypted_message = s20.decrypt(encrypted_message)
        dec_end = timeit.default_timer()
        dec_time = dec_end - dec_start
        dec_data_per_sec = len(decrypted_message) / (dec_time * 1024)

        # buat cipherfile
        output_file_path = os.path.join(output_dir_path, fn + '.enc')
        f = open(output_file_path, 'wb')
        f.write(encrypted_message)
        f.close()

        # buat file hasil dekripsi (file sebelum dienkripsi)
        output_file_path = os.path.join(output_dir_path, fn)
        f = open(output_file_path, 'wb')
        f.write(decrypted_message)
        f.close()

        row = '{},{},{:.2f},{:6.4f},{:.2f},{:6.4f},{:.2f}\n'.format(index + 1, fn, file_length, enc_time, enc_data_per_sec, dec_time, dec_data_per_sec)
        # print row
        csv.write(row)
    csv.close()

    selesai_proses = timeit.default_timer()
    waktu_keseluruhan = datetime.timedelta(seconds=selesai_proses - mulai_proses)
    print 'Selesai test_enkripsi_dekirpsi_salsa20_satu_jenis_round:', datetime.datetime.now()
    print 'Waktu yg dibutuhkan test_enkripsi_dekirpsi_salsa20_satu_jenis_round: %s' % waktu_keseluruhan
    print '<input_dir_path>: %s' % input_dir_path
    print '<keysize>: %d' % keysize
    print '<rounds>: %d' % rounds
    print '<nama_file_csv>: %s' % nama_file_csv
    print 'lokasi csv disimpan: %s' % report_dir_path
    print '-' * 50


def test_enkripsi_dekirpsi_salsa20_banyak_jenis_round(input_dir_path='', keysize=32, list_of_rounds=[8, 12, 20], nama_file_csv='hasil_test_enkripsi_dekripsi_salsa20_banyak_jenis_round.csv'):
    print '-' * 50
    print 'Mulai test_enkripsi_dekirpsi_salsa20_banyak_jenis_round:', datetime.datetime.now()
    mulai_proses = timeit.default_timer()

    # periksa keberadaan lokasi input
    if not os.path.exists(input_dir_path):
        sys.exit("WARNING: Lokasi %s tidak ditemukan!\nPeriksa kembali lokasi tersebut lalu jalankan ulang program." % input_dir_path)

    # periksa keberadaan lokasi output
    output_dir_path = os.path.join(lokasi_hasil_test, 'banyak_jenis_round')
    if os.path.exists(output_dir_path):
        sys.exit('WARNING: Folder %s sudah ada di lokasi %s\nHapus terlebih dahulu folder tersebut dan jalankan ulang program.' % ('banyak_jenis_round', lokasi_hasil_test))
    else:
        os.mkdir(output_dir_path)

    # periksa keberadaan file csv
    if os.path.exists(os.path.join(output_dir_path, nama_file_csv)):
        sys.exit('WARNING: File %s sudah ada di lokasi %s\nPakai nama yang lain atau hapus file ini kemudian jalankan ulang program.' % (nama_file_csv, output_dir_path))

    list_of_filenames = next(os.walk(input_dir_path))[2]  # hanya file saja tidak termasuk directory

    csv = open(os.path.join(output_dir_path, nama_file_csv), 'w')
    # tulis row title
    columnTitleRow = '{},{},{},{},{},{},{},{},{}\n'.format('No', 'File', 'ukuran file', 'enc_8', 'dec_8', 'enc_12', 'dec_12', 'enc_20', 'dec_20')
    csv.write(columnTitleRow)

    # loop setiap file
    for index, fn in enumerate(list_of_filenames):
        input_file_path = os.path.join(input_dir_path, fn)  # fn adalah file name
        f = open(input_file_path, 'rb')
        message = f.read()
        f.close()

        # file_type gak perlu
        # file_length = size(len(message), system=alternative)
        file_length = len(message) / 1024.0  # ubah ke dalam kilobyte/KB

        key = os.urandom(keysize)
        nonce = os.urandom(8)

        row = '{},{},{:.2f}'.format(index + 1, fn, file_length)

        for r in list_of_rounds:
            s20 = Salsa20(key, nonce, r)

            enc_start = timeit.default_timer()
            encrypted_message = s20.encrypt(message)
            enc_end = timeit.default_timer()
            enc_time = enc_end - enc_start
            # enc_data_per_sec = len(message) / (enc_time * 1024)  # KB per detik

            # cipherfile_length = size(len(encrypted_message), system=alternative)
            s20 = Salsa20(key, nonce, r)
            dec_start = timeit.default_timer()
            # gak perlu simpan decrypted_message karena di pengujian ini satu file diproses dengan tiga jenis round
            s20.decrypt(encrypted_message)
            dec_end = timeit.default_timer()
            dec_time = dec_end - dec_start
            # dec_data_per_sec = len(decrypted_message) / (dec_time * 1024)

            row += ',{:6.4f},{:6.4f}'.format(enc_time, dec_time)
        # print row
        row += '\n'
        csv.write(row)
        print('{}|{}|{}'.format(index + 1, file_length, fn))
    csv.close()

    selesai_proses = timeit.default_timer()
    waktu_keseluruhan = datetime.timedelta(seconds=selesai_proses - mulai_proses)
    print 'Selesai test_enkripsi_dekirpsi_salsa20_banyak_jenis_round:', datetime.datetime.now()
    print 'Waktu yg dibutuhkan test_enkripsi_dekirpsi_salsa20_banyak_jenis_round: %s' % waktu_keseluruhan
    print '<input_dir_path>: %s' % input_dir_path
    print '<keysize>: %d' % keysize
    print '<list_of_rounds>:', list_of_rounds
    print '<nama_file_csv>: %s' % nama_file_csv
    print 'lokasi csv disimpan: %s' % output_dir_path
    print '-' * 50

    print('=' * 50)
    selesai_proses = timeit.default_timer()
    waktu_keseluruhan = datetime.timedelta(seconds=selesai_proses - mulai_proses)
    print("Enkripsi dan dekripsi Salsa20 pada file dengan beberapa jenis round dan kunci berukuran %d" % keysize)
    print(waktu_keseluruhan)
    datetime.datetime.now()
    print('=' * 50)


def test_custom_salsa20():
    list_name_file_csv = ['s20_keysize_16.csv', 's20_keysize_32.csv']
    keysize = [16, 32]
    # list_name_file_csv berpasangan dengan keysize, mungkin kalau mau diperbaiki dengan zip kedua list
    for i in range(len(keysize)):
        test_enkripsi_dekirpsi_salsa20_banyak_jenis_round(input_dir_path=sys.argv[1], output_dir_path=sys.argv[2], keysize=keysize[i], nama_file_csv=list_name_file_csv[i])


if __name__ == '__main__':
    # main()
    if sys.argv[1] == 'satu_jenis_round':
        test_enkripsi_dekirpsi_salsa20_satu_jenis_round(input_dir_path=sys.argv[2], keysize=int(sys.argv[3]), rounds=int(sys.argv[4]))
    elif sys.argv[1] == 'banyak_jenis_round':
        list_of_rounds = [8, 12, 20]
        test_enkripsi_dekirpsi_salsa20_banyak_jenis_round(input_dir_path=sys.argv[2], keysize=int(sys.argv[3]), list_of_rounds=list_of_rounds)
    elif sys.argv[1] == 'custom':
        test_custom_salsa20()

    '''
    satu_jenis_round: python test_salsa20.py [1]satu_jenis_round [2]<input_dir_path> [3]<keysize> [4]<rounds>

    banyak_jenis_round: python test_salsa20.py [1]banyak_jenis_round [2]<input_dir_path> [3]<keysize>
    custom: python test_salsa20.py [1]custom
    '''
