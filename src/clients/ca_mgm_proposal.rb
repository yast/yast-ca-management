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
# File:
#   clients/ca_mgm_proposal.ycp
#
# Package:
#   Configuration of CA Management
#
# Summary:
#   Proposal function dispatcher.
#
# Authors:
#   Stefan Schubert <schubi@suse.de>
#
# $Id$
#
# Proposal function dispatcher for CA Management
module Yast
  class CaMgmProposalClient < Client
    def main
      Yast.import "UI"
      textdomain "ca-management"
      Yast.import "CaMgm"
      Yast.import "HTML"
      Yast.import "Label"
      Yast.import "Mode"
      Yast.import "Popup"
      Yast.import "DNS"
      Yast.import "Timezone"
      Yast.import "Users"
      Yast.import "String"
      Yast.import "Hostname"

      Yast.include self, "ca-management/new_cert_read_write.rb"
      Yast.include self, "ca-management/util.rb"

      @func = Convert.to_string(WFM.Args(0))
      @param = Convert.to_map(WFM.Args(1))
      @ret = {}

      if !CaMgm.prop_CANameChanged || CaMgm.prop_CAName == ""
        CaMgm.prop_CAName = "YaST_Default_CA"
      end
      if !CaMgm.prop_passwordChanged ||
          Ops.less_than(Builtins.size(CaMgm.prop_password), 0)
        CaMgm.prop_password = Users.GetRootPassword
      end

      if @func == "MakeProposal"
        @force_reset = Ops.get_boolean(@param, "force_reset", false)
        @proposal = ""
        @warning = nil
        @warning_level = nil

        @host_ips = getHostIPs
        @hostname_bak = ""
        if Ops.less_or_equal(Builtins.size(CaMgm.prop_subject_alt_name_list), 0)
          CaMgm.prop_subject_alt_name_list = []

          Builtins.foreach(@host_ips) do |key, value|
            @hostname_bak = key if value == "DNS"
            elem = {}
            Ops.set(elem, "kind", value)
            Ops.set(elem, "name", key)
            CaMgm.prop_subject_alt_name_list = Builtins.add(
              CaMgm.prop_subject_alt_name_list,
              elem
            )
          end
        end

        @retmap = Convert.to_map(
          SCR.Execute(path(".target.bash_output"), "/bin/hostname --long", {})
        )
        Builtins.y2milestone("Hostname :%1", @retmap)
        if Ops.get_integer(@retmap, "exit", 0) != 0 &&
            CaMgm.prop_selection == :def &&
            (!CaMgm.prop_server_commonNameChanged || !CaMgm.prop_emailChanged || @force_reset)
          if @hostname_bak == ""
            Ops.set(@retmap, "stdout", Hostname.CurrentFQ)

            if Ops.get_string(@retmap, "stdout", "linux.site") == "linux.site"
              @ret = Builtins.add(
                @ret,
                "warning",
                _(
                  "Cannot evaluate the name of the local machine. Change the values of Server Name and E-Mail."
                )
              )
              @ret = Builtins.add(@ret, "warning_level", :blocker)
            end
          else
            Ops.set(@retmap, "stdout", @hostname_bak)
          end
        end

        @longhostname = strip(Ops.get_string(@retmap, "stdout", ""))
        @longhostname = "" if @longhostname == nil # (bnc#428101)

        if Ops.less_or_equal(Builtins.size(@longhostname), 0)
          @longhostname = Hostname.CurrentFQ
        end
        @hostname = Ops.get(Builtins.splitstring(@longhostname, "."), 0, "")
        @hostname = "" if @hostname == nil # (bnc#428101)
        @domain = Builtins.substring(
          @longhostname,
          Ops.add(Builtins.findfirstof(@longhostname, "."), 1)
        )
        @domain = "" if @domain == nil # (bnc#428101)

        @domain = @longhostname if Ops.less_or_equal(Builtins.size(@domain), 0)

        if !CaMgm.prop_ca_commonNameChanged
          CaMgm.prop_ca_commonName = Ops.add(
            Ops.add("YaST Default CA (", @hostname),
            ")"
          )
        end
        if !CaMgm.prop_server_commonNameChanged
          CaMgm.prop_server_commonName = @longhostname
        end
        if !CaMgm.prop_countryChanged
          CaMgm.prop_country = Timezone.GetCountryForTimezone("")
        end
        if !CaMgm.prop_emailChanged
          CaMgm.prop_email = Ops.add("postmaster@", @domain)
        end

        return deep_copy(@ret) if Ops.get_string(@ret, "warning", "") != ""


        # new handling of force reset because of (#238754)
        if @force_reset
          Builtins.y2milestone("FORCE RESET")
          CaMgm.prop_keep_ca = false
          if CaMgm.prop_settingsWritten
            if !Popup.YesNo(
                _("CA Management") + "\n" +
                  _("Settings have already been written.") + "\n" +
                  _("Delete the old settings?")
              )
              CaMgm.prop_keep_ca = true
              @ret = { "workflow_sequence" => :auto }
            else
              @password = getPassword(CaMgm.prop_CAName)
              if @password == nil || @password == ""
                CaMgm.prop_keep_ca = true
                @ret = { "workflow_sequence" => :auto }
              else
                YaPI::CaManagement.DeleteCA(
                  {
                    "caName"   => CaMgm.prop_CAName,
                    "caPasswd" => @password,
                    "force"    => true
                  }
                )
                CaMgm.prop_settingsWritten = false
              end
            end
          else
            CaMgm.prop_selection = :def
            CaMgm.prop_ca_commonName = Ops.add(
              Ops.add("YaST Default CA (", @hostname),
              ")"
            )
            CaMgm.prop_CAName = "YaST_Default_CA"
            CaMgm.prop_country = Timezone.GetCountryForTimezone("")
            CaMgm.prop_email = Ops.add("postmaster@", @domain)
            CaMgm.prop_server_commonName = @longhostname
          end # NO FORCE RESET
        else
          @defaultRootCA = nil
          @defaultRootCA = Convert.to_map(
            YaPI::CaManagement.ReadFile(
              {
                "inFile"   => Ops.add(
                  Ops.add("/var/lib/CAM/", CaMgm.prop_CAName),
                  "/cacert.pem"
                ),
                "type"     => "parsed",
                "datatype" => "CERTIFICATE",
                "inForm"   => "PEM"
              }
            )
          )
          CaMgm.prop_settingsWritten = @defaultRootCA != nil ? true : false


          if CaMgm.prop_settingsWritten
            if CaMgm.prop_keep_ca ||
                !Popup.YesNo(
                  _("CA Management") + "\n" +
                    _("Settings have already been written.") + "\n" +
                    _("Delete the old settings?")
                )
              CaMgm.prop_keep_ca = true
              # read the details directly from the server certificate
              @defaultServerCert = Convert.to_map(
                YaPI::CaManagement.ReadFile(
                  {
                    "inFile"   => "/etc/ssl/servercerts/servercert.pem",
                    "type"     => "parsed",
                    "datatype" => "CERTIFICATE",
                    "inForm"   => "PEM"
                  }
                )
              )

              @defaultServerCertIssuer = Ops.get_map(
                @defaultServerCert,
                "ISSUER_HASH",
                {}
              )
              # CaMgm::prop_selection     = `def;
              CaMgm.prop_ca_commonName = Ops.get_string(
                Ops.get_list(@defaultServerCertIssuer, "CN", []),
                0,
                ""
              )
              CaMgm.prop_country = Ops.get_string(
                Ops.get_list(@defaultServerCertIssuer, "C", []),
                0,
                ""
              )
              CaMgm.prop_email = Ops.get_string(
                Ops.get_list(@defaultServerCertIssuer, "emailAddress", []),
                0,
                ""
              )
              CaMgm.prop_CAName = CaMgm.prop_CAName

              @defaultSCmap = Ops.get_map(@defaultServerCert, "DN_HASH", {})

              CaMgm.prop_server_commonName = Ops.get_string(
                Ops.get_list(@defaultSCmap, "CN", []),
                0,
                ""
              )


              @ret = { "workflow_sequence" => :auto }
            else
              @password = getPassword(CaMgm.prop_CAName)
              if @password == nil || @password == ""
                CaMgm.prop_keep_ca = true
                @ret = { "workflow_sequence" => :auto }
              else
                YaPI::CaManagement.DeleteCA(
                  {
                    "caName"   => CaMgm.prop_CAName,
                    "caPasswd" => @password,
                    "force"    => true
                  }
                )
                CaMgm.prop_settingsWritten = false
              end
            end
          end
        end

        if CaMgm.prop_selection == :def
          if !check_mail_address(CaMgm.prop_email)
            @ret = Builtins.add(@ret, "warning", _("Invalid e-mail format."))
            @ret = Builtins.add(@ret, "warning_level", :blocker)
          end

          if !CaMgm.prop_keep_ca &&
              Ops.less_than(Builtins.size(CaMgm.prop_password), 4)
            UI.OpenDialog(
              Opt(:decorated),
              HBox(
                VSpacing(10),
                VBox(
                  Label(
                    _(
                      "Unable to retrieve the system root password. Set a CA password to continue."
                    )
                  ),
                  HSpacing(10),
                  Password(Id(:pw1), Opt(:hstretch), _("&Password:"), ""),
                  Password(Id(:pw2), Opt(:hstretch), _("Co&nfirm Password"), ""),
                  HSpacing(10),
                  HBox(
                    PushButton(Id(:cancel), Opt(:key_F9), Label.CancelButton),
                    HStretch(),
                    PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton)
                  )
                ),
                VSpacing(10)
              )
            )
            UI.SetFocus(Id(:ok))
            while true
              @rt = UI.UserInput
              if @rt == :ok
                @pw1 = Convert.to_string(UI.QueryWidget(Id(:pw1), :Value))
                @pw2 = Convert.to_string(UI.QueryWidget(Id(:pw2), :Value))
                if @pw1 != @pw2
                  Popup.Error(_("New passwords do not match."))
                  next
                end
                if Ops.less_than(Builtins.size(@pw1), 4)
                  Popup.Error(
                    _(
                      "The password is too short to use for the certificates. \nEnter a valid password for the certificates or disable certificate creation.\n"
                    )
                  )
                  next
                end
                CaMgm.prop_password = @pw1
                CaMgm.prop_passwordChanged = true
                break
              elsif @rt == :cancel
                @ret = Builtins.add(
                  @ret,
                  "warning",
                  _(
                    "Unable to retrieve the system root password. Set a CA password to continue."
                  )
                )
                @ret = Builtins.add(@ret, "warning_level", :blocker)
                break
              end
            end

            UI.CloseDialog
          end
          if CaMgm.prop_keep_ca
            @proposal = HTML.Para(
              Ops.add(_("Current default CA and certificate."), HTML.Newline)
            )
          elsif !CaMgm.prop_passwordChanged
            @proposal = HTML.Para(
              Ops.add(
                Ops.add(_("Creating default CA and certificate."), HTML.Newline),
                _(
                  "With higher security requirements, you should change the password."
                )
              )
            )
          else
            @proposal = HTML.Para(
              Ops.add(_("Creating default CA and certificate."), HTML.Newline)
            )
          end

          @passwordString = CaMgm.prop_passwordChanged ?
            _("[manually set]") :
            _("[root password]")

          @subAltName = ""
          Builtins.foreach(CaMgm.prop_subject_alt_name_list) do |elem|
            @subAltName = Ops.add(
              Ops.add(
                Ops.add(
                  Ops.add(@subAltName, Ops.get_string(elem, "kind", "")),
                  ":"
                ),
                Ops.get_string(elem, "name", "")
              ),
              " "
            )
          end

          @proposal = Ops.add(
            @proposal,
            HTML.List(
              [
                Ops.add(_("CA Name: "), CaMgm.prop_CAName),
                Ops.add(_("Common Name: "), CaMgm.prop_ca_commonName),
                Ops.add(_("Server Name: "), CaMgm.prop_server_commonName),
                Ops.add(_("Country: "), CaMgm.prop_country),
                Ops.add(_("Password: "), @passwordString),
                Ops.add(_("E-Mail: "), CaMgm.prop_email),
                Ops.add(_("Alternative Names: "), @subAltName)
              ]
            )
          )

          if !CaMgm.prop_keep_ca &&
              Ops.less_than(Builtins.size(CaMgm.prop_password), 4)
            @ret = Builtins.add(
              @ret,
              "warning",
              _(
                "The root password is too short for use as the password for the certificates.\n Enter a valid password for the certificates or disable certificate creation.\n"
              )
            )
            @ret = Builtins.add(@ret, "warning_level", :blocker)
          end
        elsif CaMgm.prop_selection == :none
          @proposal = HTML.Para(_("Not creating a CA and certificate."))
        elsif CaMgm.prop_selection == :disk
          @proposal = HTML.Para(_("Importing a CA and certificate from file"))
        end

        @ret = Builtins.add(@ret, "preformatted_proposal", @proposal)
        if Ops.get(
            Builtins.splitstring(CaMgm.prop_server_commonName, "."),
            0,
            ""
          ) == "linux"
          @ret = Builtins.add(
            @ret,
            "warning",
            _(
              "<p>Is the default hostname <b>linux</b> really unique? The certificate is only valid if the hostname is correct.</p>"
            )
          )
        end
      elsif @func == "AskUser"
        CaMgm.prop_keep_ca = false
        @current_CAName = CaMgm.prop_CAName

        @sequence = WFM.CallFunction("ca_select_proposal", [])

        if CaMgm.prop_settingsWritten
          if !Popup.YesNo(
              _("CA Management") + "\n" +
                _("Settings have already been written.") + "\n" +
                _("Delete the old settings?")
            )
            CaMgm.prop_keep_ca = true
            @ret = { "workflow_sequence" => :auto }
          else
            @password = getPassword(@current_CAName)
            if @password == nil || @password == ""
              CaMgm.prop_keep_ca = true
              @ret = { "workflow_sequence" => :auto }
            else
              YaPI::CaManagement.DeleteCA(
                {
                  "caName"   => @current_CAName,
                  "caPasswd" => @password,
                  "force"    => true
                }
              )
              CaMgm.prop_settingsWritten = false
            end
          end
        end
      elsif @func == "Description"
        # richtext label
        @ret = {
          "rich_text_title" => _("CA Management"),
          # menu title
          "menu_title"      => _("&CA Management"),
          "id"              => "ca_mgm"
        }
      elsif @func == "Write"
        @success = true

        if !CaMgm.prop_settingsWritten
          if CaMgm.prop_selection == :def
            @success = create_default_CA_certificate
          elsif CaMgm.prop_selection == :disk
            @success = importCertificateFromDisk
          end
          CaMgm.prop_settingsWritten = true if @success
        end

        @ret = { "success" => @success }
      end
      deep_copy(@ret)
    end
  end
end

Yast::CaMgmProposalClient.new.main
