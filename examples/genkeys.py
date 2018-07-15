'''
    copyright 2018 to the Semaphore Authors

    This file is part of Semaphore.

    Semaphore is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Semaphore is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Semaphore.  If not, see <https://www.gnu.org/licenses/>.
'''

from time import time
import os
import sys
sys.path.insert(0, '../snarkWrapper')
from deploy import *


if __name__ == "__main__":

    pk_output = "../zksnark_element/pk.raw"
    vk_output = "../zksnark_element/vk.json"

    # perform the trusted setup making hte proving key ,  verification key
    if not os.path.exists(pk_output):
        genKeys(c.c_char_p(pk_output.encode()) , c.c_char_p(vk_output.encode()))

