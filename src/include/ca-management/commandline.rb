# encoding: utf-8

# ***************************************************************************
#
# Copyright (c) 2004 - 2012 Novell, Inc.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, contact Novell, Inc.
#
# To contact Novell about this file by physical or electronic mail,
# you may find current contact information at www.novell.com
#
# ***************************************************************************
# File:        include/ca-management/commandline.ycp
# Package:     Configuration of CAs
# Summary:     Commandline definitions
# Authors:     Stefan Schubert (schubi@suse.de)
#
# $Id$
module Yast
  module CaManagementCommandlineInclude
    def initialize_ca_management_commandline(include_target)
      Yast.import "UI"

      textdomain "ca-management"

      Yast.import "CaMgm"
      Yast.import "YaPI::CaManagement"

      Yast.include include_target, "ca-management/popup.rb"
      Yast.include include_target, "ca-management/util.rb"
      Yast.include include_target, "ca-management/new_cert_read_write.rb"
    end

    # Create CA via command line
    # @param option map
    # @return success
    def cmdCreateCA(options)
      options = deep_copy(options)
      new_cert_init("Root CA")
      CaMgm.CAName = Ops.get_string(options, "caname", "")
      CaMgm.commonName = Ops.get_string(options, "cn", "")
      CaMgm.emailList = [
        { "default" => true, "name" => Ops.get_string(options, "email", "") }
      ]
      CaMgm.organisationUnit = Ops.get_string(options, "ou", "")
      CaMgm.organisation = Ops.get_string(options, "o", "")
      CaMgm.locality = Ops.get_string(options, "l", "")
      CaMgm.state = Ops.get_string(options, "st", "")
      CaMgm.country = Ops.get_string(options, "c", "")
      CaMgm.validPeriod = Builtins.tointeger(
        Ops.get_string(options, "days", "365")
      )
      CaMgm.keyLength = Builtins.tointeger(
        Ops.get_string(options, "keyLength", "1024")
      )
      if Builtins.haskey(options, "keyPasswd")
        CaMgm.password = Ops.get_string(options, "keyPasswd", "")
      else
        CaMgm.password = strip(Builtins.getenv("keyPasswd"))
      end
      if !cert_write("Root CA")
        showErrorCaManagement
        return false
      end
      true
    end

    # Create a certificate via command line
    # @param option map
    # @return success
    def cmdCreateCertificate(options)
      options = deep_copy(options)
      CaMgm.CAName = Ops.get_string(options, "caname", "")
      CaMgm.currentCA = Ops.get_string(options, "caname", "")

      if Builtins.haskey(options, "capasswd")
        Ops.set(
          CaMgm.passwdMap,
          CaMgm.CAName,
          Ops.get_string(options, "capasswd", "")
        )
      else
        Ops.set(
          CaMgm.passwdMap,
          CaMgm.CAName,
          strip(Builtins.getenv("capasswd"))
        )
      end

      if Ops.get_string(options, "type", "") == "client"
        new_cert_init("Client Certificate")
      elsif Ops.get_string(options, "type", "") == "server"
        new_cert_init("Server Certificate")
      else
        CommandLine.Print(_("Wrong kind of certificate."))
        return false
      end

      CaMgm.CAName = Ops.get_string(options, "caname", "")
      CaMgm.commonName = Ops.get_string(options, "cn", "")
      CaMgm.emailList = [
        { "default" => true, "name" => Ops.get_string(options, "email", "") }
      ]
      CaMgm.organisationUnit = Ops.get_string(options, "ou", "")
      CaMgm.organisation = Ops.get_string(options, "o", "")
      CaMgm.locality = Ops.get_string(options, "l", "")
      CaMgm.state = Ops.get_string(options, "st", "")
      CaMgm.country = Ops.get_string(options, "c", "")
      CaMgm.validPeriod = Builtins.tointeger(
        Ops.get_string(options, "days", "365")
      )
      CaMgm.keyLength = Builtins.tointeger(
        Ops.get_string(options, "keyLength", "1024")
      )
      if Builtins.haskey(options, "keyPasswd")
        CaMgm.password = Ops.get_string(options, "keyPasswd", "")
      else
        CaMgm.password = strip(Builtins.getenv("keyPasswd"))
      end

      ret = true
      if Ops.get_string(options, "kind", "") == "client"
        if !cert_write("Client Certificate")
          showErrorCaManagement
          ret = false
        end
      else
        if !cert_write("Server Certificate")
          showErrorCaManagement
          ret = false
        end
      end
      ret
    end

    # Create a CRL via command line
    # @param option map
    # @return success
    def cmdCreateCRL(options)
      options = deep_copy(options)
      # generating CRL
      ret = nil
      param = {}

      if Builtins.haskey(options, "capasswd")
        Ops.set(param, "caPasswd", Ops.get_string(options, "capasswd", ""))
      else
        Ops.set(param, "caPasswd", strip(Builtins.getenv("capasswd")))
      end
      Ops.set(param, "caName", Ops.get_string(options, "caname", ""))
      Ops.set(
        param,
        "days",
        Builtins.tointeger(Ops.get_string(options, "days", "365"))
      )

      ret = YaPI::CaManagement.AddCRL(param)
      if ret == nil || ret == false
        showErrorCaManagement
        return false
      end
      ret
    end

    # Dialog for exporting CA to file
    # @param option map
    # @return true ( success )
    def cmdExportCAtoFile(options)
      options = deep_copy(options)
      param = {}
      kind = Ops.get_string(options, "certFormat", "")

      if !Builtins.haskey(options, "capasswd")
        Ops.set(options, "capasswd", strip(Builtins.getenv("capasswd")))
      end

      Ops.set(param, "caPasswd", Ops.get_string(options, "capasswd", ""))
      Ops.set(param, "caName", Ops.get_string(options, "caname", ""))
      Ops.set(param, "destinationFile", Ops.get_string(options, "file", ""))
      Ops.set(param, "exportFormat", kind)

      ret = nil
      if kind == "PKCS12" || kind == "PKCS12_CHAIN"
        if !Builtins.haskey(options, "p12passwd")
          Ops.set(options, "p12passwd", strip(Builtins.getenv("p12passwd")))
        end
        Ops.set(param, "P12Password", Ops.get_string(options, "p12passwd", ""))
      end
      ret = Convert.to_string(YaPI::CaManagement.ExportCA(param))

      Builtins.y2milestone(
        "ExportCA(to %1) return %2",
        Ops.get_string(options, "file", ""),
        ret
      )
      if ret == nil || ret != "1"
        showErrorCaManagement
        return false
      end
      true
    end

    # exporting CRL to file
    # @param option map
    # @return true ( success )
    def cmdExportCRLtoFile(options)
      options = deep_copy(options)
      param = {}

      Ops.set(param, "destinationFile", Ops.get_string(options, "file", ""))
      Ops.set(param, "exportFormat", Ops.get_string(options, "crlFormat", ""))
      Ops.set(param, "caName", Ops.get_string(options, "caname", ""))
      Ops.set(param, "caPasswd", Ops.get_string(options, "capasswd", ""))

      ret = nil
      ret = Convert.to_string(YaPI::CaManagement.ExportCRL(param))

      # delete parameter for security reason :-)
      Ops.set(param, "caPasswd", "<was set>")

      Builtins.y2milestone("ExportCRL(%1) return %2", param, ret)
      if ret == nil || ret != "1"
        showErrorCaManagement
        return false
      end
      true
    end

    # exporting Certificate to file
    # @param option map
    # @return true ( success )
    def cmdExportCertificateToFile(options)
      options = deep_copy(options)
      param = {}
      kind = Ops.get_string(options, "certFormat", "")

      if !Builtins.haskey(options, "keyPasswd")
        Ops.set(options, "keyPasswd", strip(Builtins.getenv("keyPasswd")))
      end

      Ops.set(param, "caName", Ops.get_string(options, "caname", ""))
      Ops.set(param, "caPasswd", Ops.get_string(options, "capasswd", ""))
      Ops.set(param, "certificate", Ops.get_string(options, "certname", ""))
      Ops.set(param, "exportFormat", kind)
      Ops.set(param, "destinationFile", Ops.get_string(options, "file", ""))
      Ops.set(param, "keyPasswd", Ops.get_string(options, "keyPasswd", ""))

      ret = nil
      if kind == "PKCS12" || kind == "PKCS12_CHAIN"
        if !Builtins.haskey(options, "p12passwd")
          Ops.set(options, "p12passwd", strip(Builtins.getenv("p12passwd")))
        end
        Ops.set(param, "P12Password", Ops.get_string(options, "p12passwd", ""))
      end

      ret = Convert.to_string(YaPI::CaManagement.ExportCertificate(param))

      Builtins.y2milestone(
        "ExportCertificate(to %1) return %2",
        Ops.get_string(options, "file", ""),
        ret
      )
      if ret == nil || ret != "1"
        showErrorCaManagement
        return false
      end
      true
    end
  end
end
