# DES

## About

It is the implementation of DES (only for learning purposes). DES (Data Encryption Standard) is a Symmetrica-key Encryption Algorithm. It is a Block cipher. It encrypts data of 64 bits block with a key of 56 bits (extracted from 64 bits). The same algorithm is used for both encryption and decryption.

## Usage

```bash
# make
```
For encryption
```bash
# ./bin/des -e message key
```
For decryption
```bash
# ./bin/des -d message key
```

Please enter exact 64 bits key. 

## Todo

Enhance support for message greater than 64 bits.

## Author

Tushar Sharma `tushar.sharma1729@gmail.com`

## License

```bash
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
```

